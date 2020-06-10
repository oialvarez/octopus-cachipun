package org.octopus.cachipun

import spock.lang.Specification

class Aes256CbcTest extends Specification {
    static KEY = "0101010101010101010101010101010101010101010101010101010101010101"
    static IV = "01010101010101010101010101010101"

    def "Aes 256 CBC encrypt"() {
        setup:
        def aes256Cbc = new Aes256Cbc(KEY, IV)
        def expectedText = "Everything is awesome!"
        def expectedCyphered = "F2kfsUuifRJCs5m6Xn48/sEoi88Gkxflyga8ai1pl4Y="

        when:
        def result = aes256Cbc.encryptBase64(expectedText)

        then:
        result == expectedCyphered
    }

    def "Aes 256 CBC decrypt"() {
        setup:
        def aes256Cbc = new Aes256Cbc(KEY, IV)
        def expectedText = "Everything is awesome!"
        def expectedCyphered = "F2kfsUuifRJCs5m6Xn48/sEoi88Gkxflyga8ai1pl4Y="

        when:
        def result = aes256Cbc.decryptBase64(expectedCyphered)

        then:
        result == expectedText
    }
}
