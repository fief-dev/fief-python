set dotenv-load := false

default:
  @just --list

install:
  python -m pip install --upgrade pip
  pip install flit
  flit install --deps all

isort-examples:
  isort ./examples -o fief_client

lint: isort-examples
	isort ./fief_client && isort ./tests && black . && mypy fief_client/

test:
  pytest --cov fief_client/ --cov-report=term-missing

bumpversion version:
  bumpversion {{version}}
