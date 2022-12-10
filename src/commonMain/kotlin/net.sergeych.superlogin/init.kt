package net.sergeych.superlogin

/**
 * Call it somewhere in th application before using any crypto-based methods.
 * Currently, it is mandatory for JS and is not needed on JVM platform, but
 * we recommend to call it anyway
 */
expect suspend fun InitSuperlogin()