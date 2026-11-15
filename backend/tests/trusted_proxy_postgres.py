"""Native PostgreSQL migration, restricted-role and concurrent replay acceptance.

Creates/drops only a random test-owned database and role. No provider calls.
Run against an isolated PostgreSQL19 test instance with database/role creation.
"""
import json
import os
import secrets
import subprocess
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jwt
from psycopg import sql
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app import main as module
from app.database import Base, runtime_engine
from app.main import app, db_session
from app.trusted_proxy import configuration

url = make_url(os.environ['DATABASE_URL'])
suffix = secrets.token_hex(6)
name, role = 'magpie_proxy_'+suffix, 'magpie_runtime_'+suffix
password = secrets.token_urlsafe(32)
owner = create_engine(url.set(database='postgres'), isolation_level='AUTOCOMMIT')
created_db = created_role = False
runtime = None
old_engine = module.engine
old_env = {k: os.environ.get(k) for k in ['MAGPIE_PROXY_PUBLIC_KEY_FILE', 'MAGPIE_PROXY_ISSUER',
           'MAGPIE_PROXY_AUDIENCE', 'MAGPIE_ADMIN_TOKEN', 'MAGPIE_ENCRYPTION_KEY']}
try:
    with owner.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
        created_db = True
        # Identifiers are generated locally; password is bound, never in output.
        c.exec_driver_sql(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}').format(sql.Identifier(role),sql.Literal(password)).as_string())
        created_role = True
    target = url.set(database=name)
    subprocess.run(['alembic','upgrade','0028_admin_model_tests'], check=True,
                   env=dict(os.environ, DATABASE_URL=target.render_as_string(hide_password=False)))
    test_owner = create_engine(target)
    with test_owner.begin() as c:
        c.execute(text("INSERT INTO provider_connections(name,provider_type,model_group,active) VALUES('preserved-before-upgrade','openai','general',true)"))
    subprocess.run(['alembic','upgrade','head'], check=True,
                   env=dict(os.environ, DATABASE_URL=target.render_as_string(hide_password=False)))
    with test_owner.begin() as c:
        assert c.scalar(text("SELECT count(*) FROM provider_connections WHERE name='preserved-before-upgrade'")) == 1
        c.execute(text('REVOKE CREATE ON SCHEMA public FROM PUBLIC'))
        c.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO "{role}"'))
        c.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
        for table in Base.metadata.tables:
            assert table.replace('_','').isalnum()
            c.execute(text(f'GRANT SELECT,INSERT,UPDATE,DELETE ON TABLE "{table}" TO "{role}"'))
        c.execute(text(f'GRANT SELECT ON alembic_version TO "{role}"'))
        for sequence in c.scalars(text("SELECT sequencename FROM pg_sequences WHERE schemaname='public'")):
            assert sequence.replace('_','').isalnum()
            c.execute(text(f'GRANT USAGE,SELECT ON SEQUENCE "{sequence}" TO "{role}"'))
    runtime = runtime_engine(target.set(username=role,password=password))
    with runtime.connect() as c:
        try:
            c.execute(text('CREATE TABLE public.forbidden_runtime_ddl(id int)'))
            raise AssertionError('Runtime unexpectedly has DDL authority')
        except DBAPIError:
            c.rollback()
    def get_db():
        with Session(runtime) as session:
            yield session
    app.dependency_overrides[db_session] = get_db
    module.engine = lambda: runtime
    private = ec.generate_private_key(ec.SECP256R1())
    subject = str(uuid.uuid4())
    def auth(method='GET', target='/admin/providers', body=b'', request_id=None):
        import hashlib
        now = int(time.time())
        claims = dict(iss='https://fixture.example.invalid',aud='magpie:fixture',sub=subject,
                      iat=now,nbf=now,exp=now+60,jti=request_id or str(uuid.uuid4()),actor_kind='human',
                      scope='magpie:admin:read' if method=='GET'else'magpie:admin:write',
                      method=method,target=target,body_sha256=hashlib.sha256(body).hexdigest())
        return {'authorization':'Bearer mgd_'+jwt.encode(claims,private,algorithm='ES256'),
                'content-type':'application/json'}
    with tempfile.TemporaryDirectory(prefix='magpie-proxy-key-') as tmp:
        key = Path(tmp)/'public.pem'
        key.write_bytes(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
        os.environ.update(MAGPIE_PROXY_PUBLIC_KEY_FILE=str(key),MAGPIE_PROXY_ISSUER='https://fixture.example.invalid',
                          MAGPIE_PROXY_AUDIENCE='magpie:fixture',MAGPIE_ENCRYPTION_KEY=Fernet.generate_key().decode())
        os.environ.pop('MAGPIE_ADMIN_TOKEN',None)
        configuration.cache_clear()
        with TestClient(app) as client:
            assert client.get('/health/ready').status_code == 200
            assert client.get('/admin/providers',headers=auth()).status_code == 200
            body = json.dumps({'name':'concurrent-native','provider_type':'openai'}).encode()
            request_id = str(uuid.uuid4())
            headers = auth('POST',body=body,request_id=request_id)
            def submit(_):
                return client.post('/admin/providers',content=body,headers=headers).status_code
            with ThreadPoolExecutor(max_workers=6) as executor:
                statuses = list(executor.map(submit,range(6)))
            assert statuses.count(201)==1 and statuses.count(409)==5, statuses
            target_path = '/admin/proxy-requests/'+request_id
            receipt = client.get(target_path,headers=auth(target=target_path))
            assert receipt.status_code==200 and receipt.json()['audits'][0]['action']=='provider.create'
            with test_owner.connect() as c:
                assert c.scalar(text("SELECT count(*) FROM provider_connections WHERE name='concurrent-native'"))==1
                assert c.scalar(text('SELECT count(*) FROM trusted_proxy_requests WHERE id=:id'),{'id':request_id})==1
                assert c.scalar(text('SELECT count(*) FROM admin_users'))==0
            # A failed conflicting write also consumes its identity durably.
            conflict_id=str(uuid.uuid4());headers=auth('POST',body=body,request_id=conflict_id)
            assert client.post('/admin/providers',content=body,headers=headers).status_code==409
            result=client.post('/admin/providers',content=body,headers=headers)
            assert result.status_code==409 and 'already consumed'in result.json()['detail']
    test_owner.dispose()
    print(json.dumps({'checks':['native28-to29-data-preservation','restricted-runtime-no-DDL','proxy-only-readiness-without-native-human',
        'six-concurrent-same-write-one-effect','native-audit-request-link','failed-write-nonce-survives-rollback',
        'no-native-human-copy'],'passed':7,'providerCalls':0,'productionHA':False}))
finally:
    app.dependency_overrides.clear()
    module.engine=old_engine
    configuration.cache_clear()
    for key,value in old_env.items():
        if value is None:os.environ.pop(key,None)
        else:os.environ[key]=value
    if runtime is not None:runtime.dispose()
    with owner.connect() as c:
        if created_db:c.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        if created_role:c.execute(text(f'DROP ROLE "{role}"'))
    owner.dispose()
