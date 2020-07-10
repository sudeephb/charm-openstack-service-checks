PROJECTPATH = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
DIRNAME = $(notdir $(PROJECTPATH:%/=%))

ifndef CHARM_BUILD_DIR
    CHARM_BUILD_DIR := /tmp/$(DIRNAME)-builds
    $(warning Warning CHARM_BUILD_DIR was not set, defaulting to $(CHARM_BUILD_DIR))
endif

help:
	@echo "This project supports the following targets"
	@echo ""
	@echo " make help - show this text"
	@echo " make lint - run flake8"
	@echo " make test - run the unittests and lint"
	@echo " make unittest - run the tests defined in the unittest subdirectory"
	@echo " make functional - run the tests defined in the functional subdirectory"
	@echo " make release - build the charm"
	@echo " make clean - remove unneeded files"
	@echo ""

lint:
	@echo "Running flake8"
	@tox -e lint

test: lint unittest functional

unittest:
	@tox -e unit

functional: build
	@PYTEST_KEEP_MODEL=$(PYTEST_KEEP_MODEL) \
	    PYTEST_CLOUD_NAME=$(PYTEST_CLOUD_NAME) \
	    PYTEST_CLOUD_REGION=$(PYTEST_CLOUD_REGION) \
	    CHARM_BUILD_DIR=$(CHARM_BUILD_DIR) \
	    tox -e functional

build:
	@echo "Building charm to base directory $(CHARM_BUILD_DIR)"
	@CHARM_LAYERS_DIR=./layers \
	    CHARM_INTERFACES_DIR=./interfaces \
			TERM=linux \
			CHARM_BUILD_DIR=$(CHARM_BUILD_DIR) \
			charm build . --force

release: clean build
	@echo "Charm is built at $(CHARM_BUILD_DIR)"

clean:
	@echo "Cleaning files"
	@if [ -d $(CHARM_BUILD_DIR) ] ; then rm -r $(CHARM_BUILD_DIR) ; fi
	@if [ -d $(PROJECTPATH)/.tox ] ; then rm -r $(PROJECTPATH)/.tox ; fi
	@if [ -d $(PROJECTPATH)/.pytest_cache ] ; then rm -r $(PROJECTPATH)/.pytest_cache ; fi
	@if [ -d $(PROJECTPATH)/reports ] ; then rm -r $(PROJECTPATH)/reports ; fi
	@if [ -f $(PROJECTPATH)/.coverage ] ; then rm  $(PROJECTPATH)/.coverage ; fi

# The targets below don't depend on a file
.PHONY: lint test unittest functional build release clean help
