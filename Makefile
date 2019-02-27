#!/usr/bin/make

all: lint test


.PHONY: clean
clean:
	@rm -rf .tox

.PHONY: apt_prereqs
apt_prereqs:
	@# Need tox, but don't install the apt version unless we have to (don't want to conflict with pip)
	@which tox >/dev/null || (sudo apt-get install -y python3-pip && sudo pip3 install tox)

.PHONY: lint
lint: apt_prereqs
	@tox -e pep8
	@charm proof

.PHONY: test
unit_test: apt_prereqs
	@echo Starting tests...
	tox

build:
	charm build
