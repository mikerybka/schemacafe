package schemacafe

import "embed"

func fsString(fsys embed.FS, path string) string {
	b, err := fsys.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return string(b)
}
