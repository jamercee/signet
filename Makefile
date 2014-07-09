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

include ../../common.mk

# ----------------------------------------------------------------------------
#  Build the list of target *.pyc to compile
# ----------------------------------------------------------------------------
TGTS := $(patsubst %.py,%.pyc,$(wildcard *.py))
TGTS += $(patsubst %.py,%.pyc,$(wildcard signet/*.py))
TGTS += $(patsubst %.py,%.pyc,$(wildcard tests/*.py))

.PHONY: comp clean

comp: $(TGTS)

test: comp
	@$(PYTHON) setup.py nosetests -s

install: comp
	@$(PYTHON) setup.py install

clean:
	-rm $(TGTS)

