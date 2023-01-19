# Superlogin MP library

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Current stable version 0.2.1.  

This project targets to provide command set of multiplatform tools to faciliate restore access with non-recoverable passwords by providing a backup `secret` string as the only way to reset the password. It is ready to use in android, web and server apps (native target is not yet supported because of the encryption layer not yet supporting it)

This technology is required in the systems where user data are not disclosed to anybody else, as an attempt to allow lost password reset by mean of a `secret` string that could be kept somewhere in a safe place. It allows password and protected content updates to be recoverable with a `secret`.

It also contains useful tools for this type of application:

- `BackgroundKeyGeneretor` allows to accumulate the entropy from user events and perform ahead private key generation in the background (also in JS).

- `DerivedKeys` simplify processing passwords in a safe and smart manner.

- `AccessControlObject` to contain recoverable password-protected data with a backup `secret` word to restore access.

- as it is based on [parsec3](https://gitea.sergeych.net/SergeychWorks/parsec3) library and therefore allow pushes, etc.

__Important note__. The library is yet in LTS stage, it undergoes a heavy testing in a few beta-stage commercial products, it could contain bugs and/or get incompatible updates soon. As with all free software, use it on you risk.

## Setup

It is published in the universa public mvn:
~~~
repositories {
    // ...
    maven("https://maven.universablockchain.com/")
}
~~~

and add in dependencies like:

~~~
dependencies {
    //...  
    implementation("net.sergeych:unikrypto:1.2.5")
}
~~~

## Usage with ktor server

Use module for initialization like this:
~~~
fun Application.testServerModule() {
    superloginServer(TestApiServer<TestSession>(), { TestSession() }) {
        // This is a sample of your custom API implementation:
        on(api.loginName) {
            currentLoginName
        }
    }
}
~~~
Nothe that your test session should inhert from and implement all abstract methods of `SLServerSession` abstract class to work properly.

Now you can just use the module in your ktor server initialization:
~~~
embeddedServer(Netty, port = 8082, module = Application::testServerModule).start()
~~~
Of course you can initialize superlogin server separately. In any case see autodocs for `superloginServer()` function.

On the client side it could look like:
~~~
    val api = TestApiServer<WithAdapter>()
    val slc = SuperloginClient<TestData, S1>(client)
    var rt = slc.register("foo", "passwd", TestData("bar!"))
~~~
See autodocs for `SuperloginClient` for more.


## License 

Will be published under MIT as soon as first RC will be published.


