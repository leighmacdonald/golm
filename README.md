# golm

Go Bindings for libolm, an implementation of the Double Ratchet cryptographic ratchet

## Dev setup

    git clone git@github.com:leighmacdonald/golm.git
    cd golm
    git clone https://git.matrix.org/git/olm.git olm
    cd olm
    cmake . -Bbuild
    cmake --build build
    cd ..
    go build
    
