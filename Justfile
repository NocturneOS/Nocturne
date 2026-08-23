default:
    @just --list

update:
    cargo update --recursive --workspace

clean_tree:
	git clean -dfX

