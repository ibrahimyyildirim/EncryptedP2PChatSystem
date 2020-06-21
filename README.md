## EncryptedP2PChatSystem
### 1)	Handshaking

Programda ilk olarak server tarafından port açılıyor ve client tarafından ilgili ip’ye ve porta istek atılıyor, server bu isteği kabul ederek bağlantı oluşturuluyor.

```java
    ss = new ServerSocket(1201);                 // Server 1201 port numarasında başlar
    s = ss.accept();                             // bağlantı isteği kabul etme
```

Daha sonra handshake için bir handshake metodu oluşturuldu burada ilk olarak User1(client)’den User2(server)’ye bir public key(RSA) gönderiliyor, daha sonra User2 tarafından public key alınıyor. 
```java
    public static void user1Handshake() {
        sendPublicKey();
        String nonce = getNonceAndPublicKey();
        System.out.println("Gelen nonce: " + nonce);
        sendEncryptedNonce(nonce);
        sendClientSimetricKey();
        getSimetricKey();
    }
```
User2 nonce sınıfından bir adet nonce üreterek kendi public key’i ile birlikte User1’e gönderiyor. User1 gelen nonce’u kendi private key(RSA)’i le encrypt ediyor ve bunu şifreli şekilde User2’ye gönderiyor. 
```java
public static void user2Handshake() {
        getPublicKey();                                 // user1'den ilk public key geliyor
        String nonce = sendNonceAndPublicKey();         // user2 user1'e nonce ve kendi public key'ini yolluyor
        byte[] encyrptedNonce = getEncryptedNonce();    // user1'den gelen private key'i ile şifrelenmiş Nonce
        String encString = new String(encyrptedNonce);
        System.out.println("Encyrpted nonce:" + encString);
        
         // user1'den gelen şifrelenmiş nonce user1'den gelen publicKey ile decyrpt ediliyor
        byte[] decryptedNonce = RSA.RSAEncryptDecrypt.decrypt(encyrptedNonce, publicKeyGelen);   
   
        String decString = new String(decryptedNonce);
        System.out.println("decyrpt nonce: " + decString);

        if (decString.equals(nonce)) {
            System.out.println("Handshake is done. !");
            msg_text.setEnabled(true);
            jLabel2.setText("Handshake is done.");
        } else {
            System.out.println("Handshake error !! ");   }
        getSimetricKey();
        sendServerSimetricKey();
    }
```

![1](https://github.com/ibrahimyyildirim/EncryptedP2PChatSystem/blob/master/img/1.png)<br>
**Handshake bekleniyor, mesaj alanı inaktif**

User2 daha önceden aldığı User1 public key’i ile şifreli nonce’u decrypt ediyor ve decrypt olan nonce önceden gönderdiği nonce ile aynı iste Handsake tamamlanmış oluyor ve mesaj yollamak için ekranda bulunan text alanı aktif oluyor. Ekrana “handshake is done” mesajı veriliyor. Eğer nonce’lar eşleşmezse mesaj alanı aktif olmuyor ve mesajlaşma işlemi başlamıyor.

![2](https://github.com/ibrahimyyildirim/EncryptedP2PChatSystem/blob/master/img/2.png)<br>
**Handshake tamamlandı, mesaj alanı aktif**

### 2)	Key genaration

AES ile hem User1 hem User2 tarafında simetrik key’ler oluşturuluyor. Bu key’ler iki kullanıcı arasında birbirine yollanıyor. Yazılan get ve set metodları handskahe işleminden sonra çalışıyor.
```java
   // AES simetrik key oluşturma 
    KeyGenerator keyGenerator128 = KeyGenerator.getInstance("AES");
    keyGenerator128.init(128);
    AES_server = keyGenerator128.generateKey();
```
 - Handshake tamamlandıktan sonra simetric key gönderme


```java
  if (decString.equals(nonce)) {
      System.out.println("Handshake is done. !");
      msg_text.setEnabled(true);
      jLabel2.setText("Handshake is done.");
    }
    else {
       System.out.println("Handshake Error !"); }
    getSimetricKey();
    sendServerSimetricKey();
```

Konsol ekranında giden ve gelen key’lerin gösterimi:
```sh
Gelen public key :MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP6++qWcYJMH/H8/SiXOq3ebPI6gITZfBerdkKVO1h9RvyiUqa4cyXiYXhAzFK2i5Y+6MxvYRJgZQCj8QAgoxvWY1KE0JClPzZeU76nnKrn0a3z49qByfyWrgj3zlm/vla8EaamyulLV5h+9aBBgBXu0a/gw/HJ0S8tBHU6KHdF
Giden nonce: bv5nXVVyp0gVAdnPaJObxw
Encyrpted nonce: #�Px�[`�2�ӥK�����p��s�x�ach��>��i&�	�O��Ֆ�u��Y[������
���/X���%��O�0���5c�K����&����o��� U��&��M&`||#H�ݛ�˶1�:�
decyrpt nonce: bv5nXVVyp0gVAdnPaJObxw
Gelen simetricCleintKey :q����/�%	+R�|.�����wz�
```

#### 3)	Integrity Check
User1 mesaj göndereceği zaman mesaj ve User2’nin simetric key’i ile birlikte hash’i alınıyor. H(msg+simKey) bu bizim MAC’imiz oluyor. Bu mac karşı User2’ye mesaj ile birlikte yollanıyor. User2 aldığı mesajı kendi simetric key’i ile takrar HMAC ile MAC oluşturuluyor ve MAC’ler eşleşiyorsa mesajların şifrelenip gönderilmesi için diğer adıma geçiliyor.

```java
 String SimClient = encoder.encodeToString(AES_client.getEncoded());
     //(msg+key)
     String macMsg = SimClient + msgout;

     // server'a mac oluşturması için msj gönderiliyor
    ObjectOutputStream os = new ObjectOutputStream(s.getOutputStream());
    os.writeObject(msgout);

    // HMAC
    String mac = MessageAuthenticationCode(macMsg, "key", "HmacSHA1");

    //server'a mac yollanıyor
    os.writeObject(mac);
```

![3](https://github.com/ibrahimyyildirim/EncryptedP2PChatSystem/blob/master/img/3.png)<br>
**MAC**

### 4)	Message Encryption
 - User1 mesajı ecrypt ederek User2’ye gönderiyor
 
```java
    // mesaj simetrik key ile encrypt edilerek yollanıyor
    String gidenEncMsg = AES.encrypt(msgout, AES_server);
    os.writeObject(gidenEncMsg);
```

- User2 gelen şifreli mesajı decrypt edip ekranda gösterme kısmı

```java
    if (gelenMac.equals(mac)) {
        System.out.println("MAC'ler birbirine eşit");

    //client'tan gelen şifreli mesaj alınıyor
    String gelenEncMsg = (String) in.readObject();

    // şifreli mesaj decrypt ediliyor
     byte[] decodedKey = Base64.getDecoder().decode(decSimServer);
     SecretKey origKey = new SecretKeySpec(decodedKey, "AES");
     String decMsg = AES.decrypt(gelenEncMsg, origKey);
     System.out.println("Gelen mesaj:" + gelenMesaj);
     decMsg = din.readUTF();
    // server'dan gelen mesajını görüntüleme kısmı
     msg_area_client.setText(msg_area_client.getText().trim() + "\nUser2: " + decMsg); /

     } else {
        System.out.println("exception");
     }
```
![4](https://github.com/ibrahimyyildirim/EncryptedP2PChatSystem/blob/master/img/4.png)<br>
**Program ekran görüntüleri**
