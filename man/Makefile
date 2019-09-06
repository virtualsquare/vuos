RONN=ronn
RONNOK := $(shell command -v ${RONN} 2> /dev/null)

none:

% : %.ronn
ifdef RONNOK
		grep "^\.\\\\\"" $< > $@ || true
		$(RONN) -r ${RONN_ARGS} --pipe $< >> $@
else
		echo "${RONN} is not available. Manpage $@ cannot be updated" >/dev/stderr >&2
endif
