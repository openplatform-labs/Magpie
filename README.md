# Magpie

Magpie는 생성형·판단형·임베딩 모델을 관리하기 위한 AI 게이트웨이입니다. Angular 22 + Clarity 18, Python, PostgreSQL 19를 사용합니다. Redis는 사용하지 않습니다.

## 현재 상태

개발 단계입니다. 관리자 토큰 인증, 공급자 키 암호화 저장·교체, 모델 등록, 모델별 권한을 가진 클라이언트 키 발급·폐기, 생성형 및 임베딩 API가 구현되어 있습니다. 공급자 프리셋: OpenAI, Anthropic, Gemini, EXAONE, TypeSafe Jev, OpenRouter, DeepSeek, Groq 등. 텍스트 기반 판단 API와 요청별 사용량·관리 작업 감사 이력이 구현되어 있습니다. 운영자가 허용한 HTTPS 주소를 사용자 정의 OpenAI 호환 공급자로 등록할 수 있습니다. 공급자 API 실제 호출은 테스트하지 않았으므로 모델·기능 호환성은 별도 확인이 필요합니다. 특히 EXAONE의 임베딩 모델 지원을 전제하지 않습니다.

공급자는 API 키 없이 먼저 등록하고 모델을 준비할 수 있습니다. 키 미등록 모델은 클라이언트 모델 목록에 표시되지 않으며 호출할 수 없습니다. 관리 화면의 ‘공급자 키 등록·교체’에서 나중에 키를 등록하면 사용할 수 있습니다.

공급자 등록 후 ‘연결 테스트 및 모델 불러오기’를 누르면 저장된 키로 공급자의 모델 목록 API를 조회합니다. 목록에서 모델을 선택해 생성형, 판단형 또는 임베딩 작업을 지정하고 등록할 수 있습니다. 목록 조회만으로 추론 권한이나 모델별 기능이 보장되지는 않습니다. 목록 API를 제공하지 않거나 지원되지 않는 공급자는 모델 ID를 직접 입력하세요. EXAONE 모델 목록 경로는 OpenAI 호환 경로를 사용하지만 실제 서비스와의 호환성은 검증하지 않았습니다. 조회는 버튼을 누를 때만 실행되며 테스트에는 모의 응답을 사용합니다.

Cerebras와 Novita는 각각 공식 [Cerebras 모델 목록 API](https://inference-docs.cerebras.ai/api-reference/models/list-models)와 [Novita 모델 목록 API](https://docs.novita.ai/api-reference/model-apis-llm-list-models)를 사용합니다. Fireworks는 [계정별 모델 목록 API](https://docs.fireworks.ai/api-reference/list-models)에서 공개 `fireworks` 계정만 조회하므로 개인 계정 모델은 직접 등록해야 합니다. 이 공급자들의 실제 목록·추론 호출은 테스트하지 않았습니다.

공급자 연결은 범용, 판단 전용 또는 임베딩 전용으로 구분합니다. 범용 연결에는 모델별 용도를 지정하고 전용 연결에는 해당 용도의 모델만 등록할 수 있습니다. 신규 모델은 생성형·판단형·임베딩 중 하나를 선택합니다. 기존에 여러 용도로 등록된 모델은 이관 시 유지됩니다. 관리자 API의 기존 클라이언트가 `model_group`을 생략하면 TypeSafe는 판단 전용, 그 밖의 공급자는 범용으로 등록합니다.

관리자 계정과 12시간 유효 세션, 분당 로그인 제한 및 클라이언트 키별 분당 요청 제한을 지원합니다. 운영자 인증서로 HTTPS를 종료하는 선택적 Compose 구성이 제공됩니다. 키 자동 교체 및 공급자별 상세 오류 처리는 아직 갖춰지지 않았습니다. 선택적 OIDC SSO는 미리 연결한 관리자 계정만 허용하며 실제 IdP 상호 운용성은 검증하지 않았습니다. 현재는 개발 단계이며 외부 운영 전 보안 및 배포 검증이 필요합니다.

## 로컬 실행

2026-11-14 기준 PostgreSQL 19는 RC 2이므로 `postgres:19rc2`를 사용합니다. 정식 출시 후 이미지와 호환성을 재검증합니다.

1. `.env.example`을 `.env`로 복사하고 DB 비밀번호와 `DATABASE_URL`을 일치시킵니다. URL의 특수문자는 인코딩합니다.
2. `MAGPIE_ADMIN_TOKEN`을 충분히 긴 임의 값(32~512자), `MAGPIE_ENCRYPTION_KEY`를 Fernet 키로 설정합니다. 공개 예제 토큰을 그대로 쓰면 최초 관리자 인증과 준비 상태가 거부됩니다. 예: `python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'` (cryptography 설치 필요). 두 값은 비밀로 관리합니다.
3. `docker compose up --build -d`
4. `docker compose exec backend alembic upgrade head`
5. `http://localhost:8080`에서 **처음 설정하시나요?**를 열고 `.env`의 관리자 토큰으로 연결해 첫 관리자 계정을 생성합니다. 계정으로 로그인한 뒤 공급자와 모델을 등록하세요. 첫 계정이 생성되면 부트스트랩 토큰은 더 이상 인증에 사용할 수 없습니다. 계정 로그인을 확인한 후 `.env`의 `MAGPIE_ADMIN_TOKEN`을 비우고 백엔드를 재생성할 수 있습니다. 공급자별로 실제 제공하는 모델과 기능을 선택해야 합니다.
6. 클라이언트 키를 발급하면 원문은 한 번만 표시됩니다. API 요청 시 `Authorization: Bearer <클라이언트 키>`를 사용합니다.

`.env`의 DB 비밀번호, 관리자 토큰과 암호화 키는 직접 설정합니다. 암호화 키를 교체하거나 분실하면 기존에 암호화된 공급자 키를 복호화할 수 없으므로 안전하게 백업해야 합니다. Compose는 포트를 loopback에만 바인딩합니다. `docker compose down`은 DB 볼륨을 유지합니다.

## API

- `POST /admin/users`, `POST /admin/sessions`, `DELETE /admin/sessions/current`: 계정 생성과 로그인·로그아웃
- `POST /admin/providers`, `PUT /admin/providers/{id}/key`: 공급자 등록·키 교체
- `POST /admin/providers/{id}/discover`: 공급자 모델 목록 조회 (관리자의 명시적 요청 시 외부 연결)
- `POST /admin/models`, `PUT /admin/models/{id}`: 모델 별칭, 작업 유형 및 기능 메타데이터 관리
- `POST /admin/api-keys`, `DELETE /admin/api-keys/{id}`: 클라이언트 키 발급·폐기
- `GET /v1/models`: 키에 허용된 모델 목록
- `POST /v1/chat/completions`: 생성형 호출 및 스트리밍
- `POST /v1/embeddings`: 임베딩 호출
- `PUT /admin/models/{id}/capabilities/{operation}/verification`, `GET /admin/models/{id}/verification-history`: 작업별 검증 상태 및 관리자 근거 기록
- `POST /v1/decisions`: 텍스트·이미지와 predicate·choice·score 질문을 TypeSafe Jev 또는 OpenAI Decisions로 전달
- `POST /admin/routes`, `PUT /admin/routes/{id}`, `GET /admin/routes`: 모델 라우트 관리
- `POST /admin/prices`, `GET /admin/prices`: 모델 가격 이력
- `GET /admin/metrics`, `/admin/usage`, `/admin/usage/requests`: 요청 현황과 작업·기간·모델·키별 집계 및 최근 요청
- `GET /admin/audit`: 최근 관리자 작업 이력
- `PUT /admin/api-keys/{id}/budget`, `GET /admin/budgets`: 누적 예산 및 예약금 설정
- `GET /admin/operational-status`, `PUT /admin/operational-policy`: DB 크기 및 오래된 미완료 요청·예약 상태와 조회 기준 설정
- `GET /admin/budget-reservations`, `POST /admin/budget-reservations/{request_id}/reconcile`: 미정산 예약 조회·수동 정산
- `GET/POST /admin/budget-reservations/{request_id}/adjustments`: 정산 내역 조회 및 청구액 대사. 수정 ID를 재사용해 같은 요청을 안전하게 재시도할 수 있습니다.
- `POST /admin/retention/preview`, `POST /admin/retention/apply`: 이력 삭제 미리보기·수동 적용

관리 API는 `Authorization: Bearer <관리자 토큰>`이 필요합니다. API 요청 필드는 현재 명시된 일부만 허용되며 나머지는 오류로 반환합니다. 모델 별칭은 영숫자, 점, 하이픈, 밑줄을 허용하며 공급자 모델 ID는 슬래시와 콜론도 허용합니다. 사용자 정의 공급자 주소는 운영자 허용 목록에 있어야 합니다. 공급자별로 지원하지 않는 기능은 미지원입니다. `/v1` 오류는 OpenAI 형태로 정규화하지만 완전한 호환성은 아직 검증되지 않았습니다.

모델 등록 후 호출하는 방법은 [생성형·임베딩·판단형 API 예시](docs/api-examples.md)를 참조하세요.

## 검증

- 백엔드: `cd backend && uv sync && uv run python -m pytest -q` (모의 공급자, Python 소켓의 IP 연결과 DNS 조회 차단)
- PostgreSQL 통합 검증: `docker compose exec -T backend python - < backend/tests/postgres_smoke.py` (임시 DB 생성·정리 권한 필요)
- 프런트엔드: `cd frontend && npm ci && npm run build` (Node 26 등 Angular 22 지원 버전 필요)
- API 문서: 로컬 백엔드 `/docs`

자세한 설계 및 구현 단계는 [통합 설계](docs/architecture.md), 단계별 근거와 남은 검증은 [검증 상태](docs/verification-status.md), 백업·복구는 [운영 문서](docs/operations.md)를 참조하세요.

TypeSafe 이미지 판단은 실험적 기능입니다. `/v1/decisions`에 `TypeSafe-Danger-Zone-Images: true` 헤더와 아래 형식의 JSON을 전달합니다. `<BASE64_PNG>`는 PNG 이미지의 표준 Base64 데이터로 대체하고, `image-judge`는 이미지와 Box를 지원하는 TypeSafe 모델의 등록 별칭으로 바꿉니다.

```json
{
  "model": "image-judge",
  "input": [{"type": "message", "role": "user", "content": [
    {"type": "input_text", "text": "Find the object in the image."},
    {"type": "input_image", "image_url": "data:image/png;base64,<BASE64_PNG>"}
  ]}],
  "questions": [{"type": "box", "name": "object", "instructions": "Locate the object."}]
}
```

## 판단 API와 사용량

`/v1/decisions`는 LiteLLM Decisions 형식의 텍스트 또는 인라인 이미지 `input`과 `questions` 배열을 사용합니다. TypeSafe Jev와 OpenAI 연결에서 `predicate`, `choice`, `score`를 지원합니다. `box`는 이미지 사용에 동의한 TypeSafe 연결에서만 사용할 수 있습니다. 스트리밍과 `safety_identifier`는 제공하지 않습니다. 실제 공급자 호출과 모델별 기능은 검증하지 않았습니다.

요청에 허용된 모델과 작업을 확인한 후 요청 상태를 `started`로 저장합니다. 공급자 결과에 따라 `success`, `error`, 스트림 취소 시 `interrupted`로 기록합니다. 프로세스가 비정상 종료되거나 완료 기록에 실패하면 `started`가 남을 수 있으며, 사용량 집계는 청구 원장이 아닙니다. 공급자가 사용량을 반환하지 않으면 토큰은 NULL입니다. 스트리밍 사용량은 공급자별 원본 이벤트에서 확인 가능한 값만 기록하며, 확인할 수 없는 어댑터는 미확인으로 남깁니다. 자세한 조건은 운영 문서를 참조하세요. 관리자가 모델별 가격을 등록하면 그 시점부터 가격과 토큰 또는 판단 질문 수를 기준으로 추정 비용을 계산합니다. 모델의 공급자 또는 실제 모델 ID를 바꾸면 새 가격을 등록해야 합니다. 금액은 실제 청구 금액이 아닙니다.

감사 이력은 성공한 공급자 등록·키 교체, 모델 등록, 클라이언트 키 발급·폐기를 같은 DB 트랜잭션으로 기록합니다. 계정별 로그인 성공·실패와 인증된 관리 요청의 실패도 기록합니다. 부트스트랩 작업에는 bootstrap이 기록됩니다. 프롬프트, 응답, 비밀값은 사용량과 감사 이력에 저장하지 않습니다.

## 요청 제한과 정리

관리 API의 클라이언트 키 발급에는 선택적 `Idempotency-Key`를 제공할 수 있습니다. 같은 식별자로 중복 발급을 시도하면 409를 반환하며, 최초 응답을 잃은 경우 키 원문은 복구할 수 없습니다. API 키마다 분당 허용 요청 수와 만료 시간을 설정할 수 있습니다. 제한은 DB 시계를 기준으로 하는 고정 1분 구간이며, PostgreSQL 원자적 갱신으로 인스턴스 간에 공유합니다. 경계 구간에서는 짧은 시간에 연속 두 구간의 요청이 허용될 수 있습니다. 키 폐기 및 모델·공급자 비활성화는 이후 요청부터 반영하며 이미 진행 중인 요청을 취소하지 않습니다.

오래된 제한 카운터 및 만료된 관리자 세션을 정리하려면 운영자가 정기적으로 `docker compose exec backend python -m app.maintenance`를 실행합니다. 2일이 지난 항목만 제거합니다. 요청 이력과 감사 이력은 이 명령으로 삭제하지 않습니다.
