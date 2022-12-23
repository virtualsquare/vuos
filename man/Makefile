PANDOC=pandoc
PANDOCOK := $(shell command -v ${PANDOC} 2> /dev/null)

none:

% : %.md
ifdef PANDOCOK
# copy copyright notice
		grep "^\.\\\\\"" $< > $@ || true
# run pandoc
		$(eval SECTION := $(subst .,,$(suffix $@)))
		$(eval BASENAME := $(basename $@))
		$(eval TITLE := $(shell echo "${BASENAME}\(${SECTION}\)" | tr [:lower:] [:upper:]))
		$(eval HEADER := "$(shell man ${SECTION} intro | head -1 | sed -e 's/^[^[:blank:]]*[[:blank:]]*//' -e 's/[[:blank:]]*[^[:blank:]]*$$//' )")
		$(PANDOC) -standalone -M title=${TITLE} -M section=${SECTION} -M header=${HEADER} -M footer=${PANDOC_ORG} -M "date=`date +\"%B %Y\"`" --to man $< >> $@
else
		echo "${PANDOC} is not available. Manpage $@ cannot be updated" >/dev/stderr >&2
endif
