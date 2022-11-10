# Superlogin utilities

> Work in progress, too early to use.

This project targets to provide command set of multiplatform tools to faciliate restore access with non-recoverable passwords by providing a backup `secret` string as the only way to reset the password.

This technology is required in the systems where user data are not disclosed to anybody else, as an attempt to allow lost password reset by mean of a `secret` string that could be kept somewhere in a safe place. It allows password and protected content updates to be recoverable with a `secret`.

It also contains useful tools for this type of application:

- `BackgroundKeyGeneretor` allows to accumulate the entropy from user events and perform ahead private key generation in the background (also in JS).

- `DerivedKeys` simplify processing passwords in a safe and smart manner.

- `AccessControlObject` to contain recoverable password-protected data with a backup `secret` word to restore access.

Will be published under MIT when become usable.


