default:
  @just --list

install:
  pip install -U -r requirements.dev.txt

lint:
	isort . && black . && mypy fief_client/

test:
  pytest --cov fief_client/ --cov-report=term-missing

bumpversion version:
  bumpversion {{version}}
