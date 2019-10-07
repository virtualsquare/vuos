RONN=ronn
RONNOK := $(shell command -v ${RONN} 2> /dev/null)

none:

% : %.ronn
		$(eval $@_MAN := "_")
		$(eval $@_EXT := $(suffix $@))
		$(if $(findstring .1, $($@_EXT)), $(eval $@_MAN := "v2 User Commands"), )
		$(if $(findstring .2, $($@_EXT)), $(eval $@_MAN := "v2 Programmer's Manual"), )
		$(if $(findstring .3, $($@_EXT)), $(eval $@_MAN := "v2 Programmer's Manual"), )
		$(if $(findstring .4, $($@_EXT)), $(eval $@_MAN := "v2 Special Files Manual"), )
		$(if $(findstring .5, $($@_EXT)), $(eval $@_MAN := "v2 File Formats Manual"), )
		$(if $(findstring .6, $($@_EXT)), $(eval $@_MAN := "v2 Games Manual"), )
		$(if $(findstring .7, $($@_EXT)), $(eval $@_MAN := "v2 Miscellaneous Information Manual"), )
		$(if $(findstring .8, $($@_EXT)), $(eval $@_MAN := "v2 System Manager's Manual"), )

ifdef RONNOK
		grep "^\.\\\\\"" $< > $@ || true
		$(RONN) -r ${RONN_ARGS} --manual $($@_MAN) --pipe $< >> $@
else
		echo "${RONN} is not available. Manpage $@ cannot be updated" >/dev/stderr >&2
endif
