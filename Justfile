default:
    @just --list

[working-directory: 'rust']
update:
    cargo update --recursive

clean_tree:
	git clean -dfX

