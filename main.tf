# 파일 이름: terraform_main.tf

# -----------------------------------------------------
# 취약점 1: S3 버킷을 누구나 접근 가능하도록 설정 (Public ACL)
# -----------------------------------------------------
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-public-data-bucket-987654321"

  # 취약점: ACL을 'public-read'로 설정하여 누구나 읽을 수 있게 함
  acl    = "public-read"
}

# 취약점 보완 코드 (Checkov이 이 부분을 지적할 것임)
resource "aws_s3_bucket_public_access_block" "insecure_bucket_block" {
  bucket = aws_s3_bucket.insecure_bucket.id

  # 취약점: 모든 public 접근을 허용하지 않음 (false)
  # 이 네 가지 설정은 모두 true여야 안전함!
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# -----------------------------------------------------
# 취약점 2: EC2 SSH 포트를 인터넷 전체에 개방 (0.0.0.0/0)
# -----------------------------------------------------
resource "aws_security_group" "insecure_ssh_sg" {
  name        = "insecure_ssh_sg"
  description = "Allow all inbound SSH access from the internet"

  # 취약점: SSH (22번 포트)를 인터넷 전체(0.0.0.0/0)에 개방
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # 위험! 모든 IP 허용
  }

  # 모든 아웃바운드 트래픽 허용 (일반적)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# -----------------------------------------------------
# 🔴 취약점 3 (변경): RDS 자동 백업 기능 미설정 🔴
# 데이터 손상 시 복구 수단이 없어집니다.
# -----------------------------------------------------
resource "aws_db_instance" "unencrypted_db" {
  allocated_storage    = 20
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  name                 = "mydb"
  username             = "admin"
  password             = "Password123"
  parameter_group_name = "default.mysql5.7"
  skip_final_snapshot  = true
  storage_encrypted    = true # 암호화는 안전하게 true로 설정

  # 취약점: 백업 보존 기간을 '0일'로 설정하여 자동 백업을 비활성화함
  # main.tf 파일에 추가
  # 테스트용 새 주석
  # 테스트용 새 주석 2
  # 테 새 주 3
  # 테 새 주 4
  # This is a test change for the AI bot PR.
  backup_retention_period = 0
}