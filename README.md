# stellite-card-applet
A javacard applet for secure, low cost stellitepay hardware wallet. 

This project is an attempt to create low cost but secure hardware wallet, to be able to do transaction with StellitePay. Using [Javacard](https://en.wikipedia.org/wiki/Java_Card), we could implement basic data storage and cryptographical task securely in within card.

Some advantages in using a smartcard to do transaction
* **Offline device**. Use it like you are using your credit/debit card on merchant POS. Imagine your are overseas, with phone battery run out or not within cellular coverage, but you need to pay using StellitePay securely.
* **End to end Security**. As all transaction is encrypted by default from card to stellitepay server. See [security design](https://github.com/Ereddon/stellite-card-applet/wiki/Security-Design), there is no way merchant could sniff, see or steal your data while doing transaction. 
* **User friendly**. Well, it is just a plastic card reside in your pocket.
* **Theft-proof**. The card is protected by PIN. Don't you worry about it being stolen. Just build another one.
* **DIY**. Built you own card offline at home is encouraged. Your credential are not to shared with anyone else.

# a glimpse look at the security design

![](https://s8.postimg.cc/frfmasiol/Stellite_Card_txs_model_draft_02_rev2.png)

This is yet to be final design, but open, peer-reviewed security design are preferred to be used as a foundation. Pros review are encouraged to make it a really good security design. 

*NOTE : currently under development and no usable code available yet*
