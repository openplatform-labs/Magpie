"""Exercise legacy price migration in a disposable PostgreSQL database."""
import os
import secrets
import subprocess
from decimal import Decimal

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app import observability
from app.main import PriceIn, create_price
from app.models import ModelPrice, UsageRecord

url = make_url(os.environ['DATABASE_URL'])
admin = create_engine(url.set(database='postgres'), isolation_level='AUTOCOMMIT')
name = 'magpie_price_' + secrets.token_hex(6)
with admin.connect() as connection:
    connection.execute(text(f'CREATE DATABASE "{name}"'))
test_url = url.set(database=name)
test_engine = create_engine(test_url)
env = dict(os.environ, DATABASE_URL=test_url.render_as_string(hide_password=False))
try:
    subprocess.run(['alembic','upgrade','0021_usage_resolution'], env=env, check=True)
    with test_engine.begin() as connection:
        connection.execute(text("INSERT INTO provider_connections (id,name,provider_type,active) VALUES (1,'mock','openai',true)"))
        connection.execute(text("INSERT INTO provider_connections (id,name,provider_type,active) VALUES (2,'jev','typesafe',true)"))
        connection.execute(text("INSERT INTO model_registrations (id,alias,upstream_model,provider_id,active) VALUES (1,'multi','mock',1,true)"))
        connection.execute(text("INSERT INTO model_capabilities (model_id,operation,api_mode) VALUES (1,'generation','chat_completions'),(1,'embedding','embeddings'),(1,'decision','decisions')"))
        connection.execute(text("INSERT INTO client_keys (id,name,key_hash,key_prefix,active) VALUES (1,'mock','fakehash','mgp_test',true)"))
        connection.execute(text("INSERT INTO model_prices (id,model_id,effective_from,currency,basis,input_per_million,output_per_million) VALUES (1,1,now(),'USD','tokens',1,2)"))
        connection.execute(text("INSERT INTO model_prices (id,model_id,effective_from,currency,basis,per_question) VALUES (2,1,now(),'USD','question',0.2)"))
        connection.execute(text("INSERT INTO usage_records (request_id,client_key_id,model_id,operation,status,started_at,finished_at,price_id,estimated_cost,currency) VALUES ('historical',1,1,'generation','success',now(),now(),1,42,'USD')"))
        connection.execute(text("SELECT setval(pg_get_serial_sequence('model_prices','id'), 2)"))
    subprocess.run(['alembic','upgrade','head'], env=env, check=True)
    with test_engine.connect() as connection:
        assert connection.execute(text('SELECT id, model_group FROM provider_connections ORDER BY id')).all() == [(1, 'general'), (2, 'decision')]
        assert connection.execute(text('SELECT count(*) FROM model_capabilities WHERE model_id = 1')).scalar_one() == 3
    with Session(test_engine) as session:
        assert session.get(ModelPrice, 1).operation is None
        assert session.get(ModelPrice, 2).operation == 'decision'
        historical = session.get(UsageRecord, 'historical')
        assert historical.price_id == 1 and historical.estimated_cost == Decimal('42')
        assert historical.provider_id_snapshot is None and historical.upstream_model_snapshot is None
        request, _ = observability.begin(session, 1, 1, 'generation', pricing_version=1)
        assert session.get(UsageRecord, request).price_id is None
        decision, _ = observability.begin(session, 1, 1, 'decision', pricing_version=1)
        assert session.get(UsageRecord, decision).price_id == 2
        create_price(PriceIn(model_id=1, operation='generation', currency='USD', basis='tokens', input_per_million=1, output_per_million=2), session, 'operator')
        request, _ = observability.begin(session, 1, 1, 'generation', pricing_version=1)
        assert session.get(UsageRecord, request).price_id not in (None, 1, 2)
    downgrade = subprocess.run(['alembic','downgrade','0021_usage_resolution'], env=env, capture_output=True, text=True)
    assert downgrade.returncode != 0
    print('Legacy prices remain historical; ambiguous token prices require operation-specific replacement.')
finally:
    test_engine.dispose()
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE "{name}"'))
    admin.dispose()
