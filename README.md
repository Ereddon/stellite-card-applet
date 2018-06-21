# stellite-card-applet
A javacard applet for secure, low cost hardware wallet for StellitePay

This project is an attempt to create low cost but secure hardware wallet, to be able to do transaction with StellitePay. Using [Javacard](https://en.wikipedia.org/wiki/Java_Card), we could implement basic data storage and cryptographical task securely in within card.

Some advantages in using a smartcard to do transaction
* **Offline device**. Use it like you are using your credit/debit card on merchant POS. Imagine your phone battery run out or not within cellular coverage, but you need to pay using StellitePay.
* **Secure**. As all transaction is encrypted by default see [security design](https://github.com/Ereddon/stellite-card-applet/wiki/Security-Design), there is no way merchant could see and steal your data. 
* **User friendly**. Well, it is just a card reside in your pocket.
* **Theft-proof**. The card is protected by PIN. Don't you worry about it being stolen. Just build another one.
* **DIY**. Built you own card offline at home is encouraged. Your credential are not to shared with anyone else.

