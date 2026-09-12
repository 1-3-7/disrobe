module depfix

go 1.26.3

require example.com/depmod v1.4.2

replace example.com/depmod => ./internal/depmod
