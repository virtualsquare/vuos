RONN=ronn
RONNOK := $(shell command -v ${RONN} 2> /dev/null)

none:

% : %.ronn
ifdef RONNOK
# copy copyright notice
		grep "^\.\\\\\"" $< > $@ || true
# run ronn
		$(RONN) -r ${RONN_ARGS} --pipe $< >> $@
# delete useless trailing "" in .TH
		sed -i '/^\.TH /s/ ""$$//' $@
else
		echo "${RONN} is not available. Manpage $@ cannot be updated" >/dev/stderr >&2
endif
