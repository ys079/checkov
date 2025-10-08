# 파일 이름: main.py
import os
import json
import sys
import requests
import logging
from dotenv import load_dotenv

# Google Gemini API 라이브러리
from google import genai
from google.genai import types 
# API 호출 오류 처리를 위한 라이브러리 (pip install google-api-core 필요)
from google.api_core.exceptions import GoogleAPICallError

# 로깅 설정 (터미널에 상세 로그 출력)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# -----------------------------------------------------
# 환경 변수 로드 (로컬 테스트용)
# GHA에서는 이 코드가 실행되지 않지만, 로컬 테스트를 위해 필요합니다.
load_dotenv()

# -----------------------------------------------------
# 상수 설정 (로컬 테스트용 기본값)
# -----------------------------------------------------
GITHUB_REPOSITORY_DEFAULT = "ys079/checkov"
TEST_PR_NUMBER_DEFAULT = 1

# -----------------------------------------------------
# [1] 스캔 결과 파일 읽기 및 간결화
# -----------------------------------------------------
def read_scan_result(file_path):
    """지정된 경로의 JSON 파일을 읽고, AI에게 필요한 핵심 정보만 추출합니다."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
            
            # 오류 수정 로직: 최상위 객체가 리스트인지 딕셔너리인지 확인하고 처리
            if isinstance(raw_data, list) and raw_data:
                # Checkov 결과가 [ { ... } ] 형태로 나오는 경우 (리스트의 첫 번째 요소 사용)
                data_to_process = raw_data[0]
            elif isinstance(raw_data, dict):
                # 최상위 객체가 예상대로 딕셔너리인 경우
                data_to_process = raw_data
            else:
                logger.error(f"JSON 데이터 형식이 유효하지 않습니다. (type: {type(raw_data)})")
                return None
            
            # 'results' -> 'failed_checks' 경로를 따라 핵심 취약점 목록 확보
            failed_checks = data_to_process.get('results', {}).get('failed_checks', [])
            
            summary = []
            for check in failed_checks:
                # AI에게 필요한 핵심 정보만 선택적으로 추출하여 리스트에 추가
                summary.append({
                    "check_id": check.get("check_id"),
                    "severity": check.get("severity", "MEDIUM"),
                    "resource": check.get("resource"),
                    "file_path": check.get("file_path"),
                    "vulnerable_lines": check.get("code_block") # 취약한 코드 블록 전달
                })

            # 간결화된 데이터를 JSON 문자열로 변환하여 AI 프롬프트에 사용
            return json.dumps(summary, indent=2)
            
    except FileNotFoundError:
        logger.error(f"❌ 오류: {file_path} 파일을 찾을 수 없습니다. Checkov 스캔을 먼저 실행하세요.")
        # GHA에서는 다음 단계로 넘어갈 수 없으므로 시스템 종료
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ 오류: JSON 파일 처리 중 문제 발생 - {e}")
        # GHA에서는 다음 단계로 넘어갈 수 없으므로 시스템 종료
        sys.exit(1)


# -----------------------------------------------------
# [2] AI 분석 요청 및 리뷰 코멘트 생성 (Gemini API 호출)
# -----------------------------------------------------
def get_ai_analysis(api_key, summary_data):
    """스캔 결과를 Gemini API에 보내 분석을 요청하고, 그 답변을 받습니다."""
    
    client = genai.Client(api_key=api_key)

    SYSTEM_INSTRUCTION = (
        "당신은 친절하고 유능한 시니어 보안 엔지니어입니다. 후배 개발자가 이해하기 쉽도록 "
        "아래의 [Checkov 스캔 결과]를 분석해 리뷰를 작성합니다. "
        "답변 형식은 반드시 Markdown을 사용하고, 한국어로 작성해야 합니다."
    )
    
    PROMPT = f"""
    이 IaC 코드에 대한 친절한 보안 검토를 요청합니다.

    다음 규칙을 반드시 지켜주세요:
    1. 전체적인 요약으로 시작해주세요.
    2. 각 취약점에 대해 '문제점', '위험성', '해결 방안(수정 코드 예시 포함)'을 명확히 구분하여 설명해주세요.
    3. 수정 코드는 정확한 Terraform 형식의 코드 블록(```terraform ... ```)으로 제시해야 합니다.

    [Checkov 스캔 결과]
    {summary_data}
    """
    
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash', # 빠르고 효율적인 모델 선택
            contents=PROMPT,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION
            )
        )
        return response.text
    
    except GoogleAPICallError as e:
        logger.error(f"❌ 오류: Gemini API 호출 실패 (Key/할당량 오류) - {e}")
        return None
    except Exception as e:
        logger.error(f"❌ 오류: AI 분석 중 예기치 않은 문제 발생 - {e}")
        return None


# -----------------------------------------------------
# [3] GitHub PR에 코멘트 작성 (출력)
# -----------------------------------------------------
def post_github_comment(token, repo_slug, pr_number, comment_body):
    """GitHub PR에 코멘트를 작성합니다."""
    
    try:
        owner, repo_name = repo_slug.split('/')
    except ValueError:
        logger.error(f"❌ 오류: 저장소 슬러그 형식이 잘못되었습니다. (예: user/repo) - {repo_slug}")
        return False
        
    # 이슈 번호 (PR 번호)를 사용하여 댓글 API URL 구성
    url = f"https://api.github.com/repos/{owner}/{repo_name}/issues/{pr_number}/comments"
    
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {"body": comment_body}

    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status() 
        logger.info(f"✅ GitHub에 코멘트를 성공적으로 작성했습니다. (PR #{pr_number})")
        return True
    except requests.exceptions.HTTPError as e:
        logger.error(f"❌ 오류: GitHub 코멘트 작성 실패 - {e}")
        logger.error(f"Status Code: {response.status_code}. Response Text: {response.text}")
        logger.error("💡 힌트: GITHUB_PAT에 'repo' 권한이 있는지, PR 번호가 유효한지 확인하세요.")
        return False


# -----------------------------------------------------
# [4] 메인 함수 실행
# -----------------------------------------------------
if __name__ == "__main__":
    
    # GHA 또는 로컬 환경 변수에서 키와 PR 정보를 로드 (우선순위: OS 환경 변수 > .env 파일)
    gemini_key = os.getenv("GEMINI_API_KEY")
    github_token = os.getenv("GITHUB_PAT")
    
    # GHA에서 전달받는 환경 변수 (PR_NUMBER, GITHUB_REPOSITORY) 로드
    # 로컬 테스트 시에는 하드코딩된 기본값을 사용합니다.
    repo_slug = os.getenv("GITHUB_REPOSITORY", GITHUB_REPOSITORY_DEFAULT) 
    pr_number_str = os.getenv("PR_NUMBER")
    
    try:
        # GHA에서 PR_NUMBER가 있으면 사용하고, 없으면 로컬 테스트 기본값을 사용
        pr_number_to_use = int(pr_number_str) if pr_number_str else TEST_PR_NUMBER_DEFAULT
    except (TypeError, ValueError):
        logger.error("❌ 오류: PR_NUMBER가 유효한 숫자가 아닙니다.")
        sys.exit(1)


    if not gemini_key:
        logger.error("❌ 오류: GEMINI_API_KEY가 설정되지 않았습니다.")
        sys.exit(1)
    
    if not github_token:
        logger.error("❌ 오류: GITHUB_PAT가 설정되지 않았습니다.")
        sys.exit(1)
        
    logger.info("--- AI 보안 리뷰 봇 (Gemini) 실행 시작 ---")
    
    # 2. 스캔 결과 파일 읽기 및 간결화
    summary_data = read_scan_result("findings.json")

    if summary_data:
        logger.info("✅ JSON 분석 데이터 준비 완료.")

        # 3. AI에게 분석 요청
        logger.info("🧠 Gemini API에 리뷰 코멘트 생성 요청 중...")
        ai_comment = get_ai_analysis(gemini_key, summary_data)

        if ai_comment:
            # 4. GitHub에 댓글 게시
            logger.info("--- AI 생성 결과 미리보기 ---")
            print(ai_comment)
            logger.info("------------------------------")
            
            # GHA 또는 로컬에서 설정된 최종 값을 사용하여 댓글 게시
            post_github_comment(github_token, repo_slug, pr_number_to_use, ai_comment)