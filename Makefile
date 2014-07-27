# ----------------------------------------------------------------------------
#  Signet Makefile. 
#
#  Available Recipes
#
#	build 	- invoke 'python setup.py build'
#	clean   - remove intermediate build targets
#	comp 	- perform python static analysis (compile *.py -> *.pyc)
#	docs 	- build signet documentation (docs/_build/html && README.md)
#			  (requires pandoc -- http://johnmacfarlane.net/pandoc/)
#	install - invoke 'python setup.py install'
#	test 	- run signet unittests
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
#  Implicit rule perform python static analysis. We refer to this
#  as compiling. To only analyze python modules that have changed,
#  we compile *.py -> *.pyc after each static analysis pass.
# ----------------------------------------------------------------------------
%.pyc:	%.py
	@echo Check $<
	@$(PYLINT) -rn --rcfile pylint.rc $<
	@$(PYTHON) -c 'import py_compile; py_compile.compile("$<")'

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
	cd docs && $(MAKE) html
	pandoc -f rst -t markdown -o README.md docs/index.rst

clean:
	-rm $(TGTS)
	$(PYTHON) setup.py clean

publish:
	@chg=`git status -s|wc -l`; \
	if [ $$chg -ne 0 ]; \
	then \
		  echo "Run 'git commit ..' before publish"; \
		  exit -1; \
	fi
	git checkout gh-pages
	git rm -r .
	git checkout master -- docs/_build/html
	git mv docs/_build/html/* .
	git commit -a -m "update docs"
	git push origin gh-pages
	git checkout master

