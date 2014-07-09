# ----------------------------------------------------------------------------
#  Used to perform static analysis of the client code
#  (and libraries) for this platform.
#
#  Available Recipes
#
#  		comp  - compile *.py -> *.pyc for this platform
#  		clean - remove any compiled code
#
# ----------------------------------------------------------------------------

ifeq ($(OS), Windows_NT)
	OSTYPE := Windows
	PYTHON := C:/Python27/python.exe
	PYLINT := C:/Python27/Scripts/pylint
	FIND   := /usr/bin/find
else
	OSTYPE := $(shell uname)
	OSREL  := $(shell uname -r)
	SHELL  := $(shell which bash)
	export SHELL
	PYTHON := python2.7
	PYLINT := pylint
	FIND   := find
endif

PYARCH := $(shell $(PYTHON) -c "import platform; print platform.architecture()[0]")

# ----------------------------------------------------------------------------
#  Implicit rule to compile *.py -> *.pyc
#	@$(PYLINT) -rn --include-ids=y --rcfile pylint.rc $<
# ----------------------------------------------------------------------------
%.pyc:	%.py
	@echo Check $<
	@$(PYLINT) -rn --rcfile pylint.rc $<
	@$(PYTHON) -c 'import py_compile; py_compile.compile("$<")'

%.pln: %.pyx
	@echo Check $<
	@$(PYLINT) -rn --rcfile pylint.rc $<
	@touch $@

# ----------------------------------------------------------------------------
#  Build the list of target *.pyc to compile
# ----------------------------------------------------------------------------
TGTS := $(patsubst %.py,%.pyc,$(wildcard *.py))
TGTS += $(patsubst %.py,%.pyc,$(wildcard signet/*.py))
TGTS += $(patsubst %.py,%.pyc,$(wildcard signet/command/*.py))
TGTS += $(patsubst %.py,%.pyc,$(wildcard tests/*.py))

.PHONY: comp test build install docs clean

comp: $(TGTS)

test: comp
	$(PYTHON) setup.py develop
	$(PYTHON) setup.py nosetests -s

build: comp
	$(PYTHON) setup.py build

install: comp
	$(PYTHON) setup.py install

docs:
	sphinx-build -b html . docs

clean:
	-rm $(TGTS)
	$(PYTHON) setup.py clean

