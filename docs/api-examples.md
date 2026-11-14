# Magpie API 시작하기

이 예시는 Magpie 게이트웨이로 요청을 보내는 방법입니다. 아래 명령은 자동으로 실행되지 않습니다. 실제로 실행하면 선택한 공급자의 API가 호출되고 비용이 발생할 수 있습니다.

## 준비

1. 관리 화면에서 사용할 공급자를 등록하고 API 키를 입력합니다. 공급자 키 없이 모델을 미리 등록할 수 있지만, 호출하려면 나중에 키를 등록해야 합니다.
2. 사용할 모델을 등록합니다. 아래 예시의 `chat-main`, `embed-main`, `judge-main`은 Magpie에서 정한 **모델 별칭**으로 바꾸세요. 각 모델에서 생성형, 임베딩 또는 판단형 작업을 선택해야 합니다. 같은 모델이 여러 작업을 지원한다면 함께 선택할 수 있습니다.
3. **API 키** 메뉴에서 해당 모델에 대한 권한이 있는 클라이언트 키를 발급합니다. 키 원문은 발급 직후 한 번 표시됩니다. 공급자 키가 아닌 이 클라이언트 키를 호출에 사용합니다.

예시는 기본 Docker 포트 `http://127.0.0.1:8080`을 사용합니다. 다른 주소로 실행한다면 `MAGPIE_URL`을 변경하세요. 아래 입력은 셸 화면에 키를 표시하지 않습니다.

```bash
export MAGPIE_URL='http://127.0.0.1:8080'
printf 'Magpie 클라이언트 키: '
read -r -s MAGPIE_CLIENT_KEY
printf '\n'
export MAGPIE_CLIENT_KEY
```

## 사용 가능한 모델

```bash
curl --fail-with-body "$MAGPIE_URL/v1/models" \
  -H "Authorization: Bearer $MAGPIE_CLIENT_KEY"
```

키에 허용된 활성 모델 중 공급자 키가 등록된 모델이 표시됩니다. 이 목록은 공급자 키의 실제 유효성이나 모델의 실제 기능을 확인하지 않습니다.

## 생성형

```bash
curl --fail-with-body "$MAGPIE_URL/v1/chat/completions" \
  -H "Authorization: Bearer $MAGPIE_CLIENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"chat-main","messages":[{"role":"user","content":"안녕하세요"}]}'
```

스트리밍을 사용하려면 요청에 `"stream": true`를 추가하고 `curl`에 `-N` 옵션을 사용합니다. 스트리밍은 모델과 공급자별 지원 조건을 따릅니다.

## 임베딩

```bash
curl --fail-with-body "$MAGPIE_URL/v1/embeddings" \
  -H "Authorization: Bearer $MAGPIE_CLIENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"embed-main","input":"검색할 문장"}'
```

`input`에 문자열 배열을 전달해 배치할 수 있습니다. 모델 등록 시 지정한 차원이나 배치 제한은 요청 전에 검사합니다. 공급자가 실제로 임베딩을 제공하는지는 해당 모델을 기준으로 확인해야 합니다.

## 판단형

TypeSafe Jev 또는 OpenAI 판단 모델을 `judge-main` 별칭으로 등록한 예시입니다.

```bash
curl --fail-with-body "$MAGPIE_URL/v1/decisions" \
  -H "Authorization: Bearer $MAGPIE_CLIENT_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"judge-main","input":"고객이 제품을 반품하려 합니다.","questions":[{"type":"predicate","name":"return_intent","instructions":"반품 의사가 있습니까?"}]}'
```

판단 결과의 확률은 업무 데이터로 평가해 사용하세요. 이미지 및 Box 질문의 조건은 [운영 문서](operations.md)의 TypeSafe 이미지 판단 항목을 참조하세요.

## 사용량과 감사 이력

관리 화면의 **사용량 · 감사**에서 작업 유형별 요청과 관리자 작업을 확인합니다. 공급자가 사용량을 반환하지 않은 경우 토큰 수는 미확인으로 표시됩니다. 키 원문이나 요청 본문은 이 이력에 저장하지 않습니다. 사용을 마친 셸에서는 `unset MAGPIE_CLIENT_KEY`로 환경 변수를 지울 수 있습니다.
