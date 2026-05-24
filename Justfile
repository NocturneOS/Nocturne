default:
    @just --list

update:
    cargo update --recursive

clean_tree:
	git clean -dfX

