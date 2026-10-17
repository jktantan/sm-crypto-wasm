import { computed } from 'vue';
import { useData } from 'vitepress';

/**
 * Playground 组件的三语文案表。
 *
 * 组件本身与语言无关（`sm4.encryptCBC(...)` 在哪种语言下都一样），但表单标签、
 * 按钮、结果说明这些**面向读者的文案**必须跟随站点语言 —— 否则英文/俄文页面里
 * 会中英混排。这里把全部文案集中成一张表，组件用 `usePgText()` 取当前语言的一份。
 *
 * 键名约定：与组件里的表单字段一一对应（label / hint / title / desc / code）。
 */

type Lang = 'zh' | 'en' | 'ru';

function normalizeLang(lang: string): Lang {
  if (lang.startsWith('ru')) return 'ru';
  if (lang.startsWith('en')) return 'en';
  return 'zh';
}

const TEXT = {
  zh: {
    frame: { run: '运行', running: '运行中…', src: '等效代码' },
    sm3: {
      title: 'SM3 摘要与 HMAC-SM3',
      desc: '点「运行」会先加载 sm3.wasm，再对上面填的消息真跑一遍 hash 与 hmac。',
      code: `import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();          // 首次使用前预热 wasm（异步）
sm3.hash('abc');                   // → 32 字节摘要的 hex
sm3.hmac(key, 'abc');              // → 32 字节 HMAC 的 hex`,
      msgLabel: '消息',
      msgHint: '任意长度（含空串）',
      msgEncLabel: '消息编码',
      keyLabel: 'HMAC 密钥',
      keyHint: '16 字节 hex',
      keyEncLabel: '密钥编码',
      hashKey: 'sm3.hash(msg)',
      hmacKey: 'sm3.hmac(key, msg)',
    },
    sm4: {
      title: 'SM4 加解密（ECB / CBC / CTR / CFB / OFB / GCM）',
      desc: '切换模式与方向，填好密钥后运行。ECB 不做填充，明文必须是 16 字节的整数倍；CBC 带 PKCS#7 填充；GCM 是 AEAD，会额外给出认证标签。',
      code: `import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
sm4.encryptCBC(key, iv, 'abc');                    // 任意长度，内部 PKCS#7 填充
sm4.encryptCTR(key, iv, 'abc');                    // 流模式，等价 decryptCTR
const { ct, tag } = sm4.encryptGCM(key, iv, 'abc', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);             // 认证失败抛 DecryptionError`,
      modeLabel: '模式',
      dirLabel: '方向',
      dirEncrypt: '加密',
      dirDecrypt: '解密',
      keyLabel: '密钥 key',
      keyHint: '16 字节 hex',
      ivLabel: '初始向量 iv',
      ivHint: '16 字节 hex（GCM 常用 12 字节）',
      inputLabel: '输入',
      inputHint: '加密时是明文，解密时是密文',
      encLabel: '输入编码',
      aadLabel: '附加认证数据 aad',
      aadHint: '可留空',
      tagLabel: '认证标签 tag',
      tagHint: '16 字节 hex，来自 encryptGCM',
      randomLabel: '随机 key / iv',
      outKey: (mode: string, dir: string) => `${mode} · ${dir} 输出（hex）`,
      tagKey: 'tag（GCM 认证标签）',
      utf8Key: '按 UTF-8 还原',
    },
    sm2: {
      title: 'SM2 密钥对、签名/验签、加密/解密',
      desc: '一次运行跑完整链路：生成密钥对（首次）→ SM3withSM2 签名 → 验签 → 加密 → 解密，另跑一次 KEM + SM4-GCM 混合加密。密钥用 PKCS#8 / SPKI PEM，和 openSSL、GmSSL 的互操作格式一致。',
      code: `import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');       // 默认 SM3withSM2，输出 r||s 的 hex
sm2.verify(publicKeyPem, 'abc', sig);             // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');      // 默认 C1C3C2
sm2.decrypt(privateKeyPem, ct);                   // 解密端自动识别密文顺序

const sealed = sm2.hybridEncrypt(publicKeyPem, 'abc');  // KEM + SM4-GCM
sm2.hybridDecrypt(privateKeyPem, sealed);              // → '616263'`,
      regenLabel: '重新生成密钥对',
      formatLabel: '密文分量顺序',
      msgLabel: '消息',
      msgHint: '按 UTF-8 编码后签名 / 加密',
      privLabel: '私钥（PKCS#8 PEM）',
      pubLabel: '公钥（SPKI PEM）',
      sigKey: 'sm2.sign() → 签名 r‖s',
      verifyKey: 'sm2.verify()',
      ctKey: (fmt: string) => `sm2.encrypt() → 密文（${fmt}）`,
      ptKey: 'sm2.decrypt() → 明文',
      hybridKey: 'sm2.hybridEncrypt() → sealed（KEM + SM4-GCM）',
      hybridPtKey: 'sm2.hybridDecrypt() → 明文',
      yes: 'true（验签通过）',
      no: 'false（验签失败）',
    },
    sm9: {
      title: 'SM9 标识密码：签名 / 加密 / 密钥封装',
      desc: '首次运行会生成两套主密钥（签名与加密各一套，共约 4 ms），随后跑签名→验签、加密→解密、KEM 封装→解封装，以及一次 KEM + SM4-GCM 混合加密。标识 id 就是公钥，没有证书链。',
      code: `import { sm9 } from 'sm-crypto-wasm';

const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });              // purpose 默认 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', 'abc');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', 'abc');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);

const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);      // === key

const sealed = sm9.hybridEncrypt(encKp.masterPublicPem, 'alice@foo.com', 'abc');
sm9.hybridDecrypt(encKp.masterPrivatePem, 'alice@foo.com', sealed);              // → '616263'`,
      idLabel: '用户标识 id',
      idHint: '公钥就是它；改了要重新生成密钥对',
      msgLabel: '消息',
      msgHint: '按 UTF-8 编码',
      klenLabel: 'KEM 会话密钥长度（字节）',
      klenHint: 'klen，默认 32',
      showKeys: '查看本次生成的主密钥（PEM）',
      signKey: 'sm9.sign() → h‖Sx‖Sy',
      verifyKey: 'sm9.verify()',
      ctKey: (bytes: number) => `sm9.encrypt() → 密文（${bytes} 字节）`,
      ptKey: 'sm9.decrypt() → 明文',
      kemKey: 'sm9.kemEncrypt() → 会话密钥 K',
      kemCheckKey: 'sm9.kemDecrypt() → 解封装的 K 是否一致',
      hybridKey: 'sm9.hybridEncrypt() → sealed（KEM + SM4-GCM）',
      hybridPtKey: 'sm9.hybridDecrypt() → 明文',
      yes: 'true（验签通过）',
      no: 'false（验签失败）',
      match: '一致 ✓',
      mismatch: '不一致 ✗',
    },
    zuc: {
      title: 'ZUC EEA3 机密性 + EIA3 完整性',
      desc: '同一份密钥流既做 EEA3 加解密，也能算 EIA3 的 32 位 MAC。每次点运行会自增 counter —— 重复用同一个 (key, iv, counter) 加密是机密性事故，库会直接抛错。',
      code: `import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
zuc.zucKeystream(key, iv, 16);                     // → Uint8Array 密钥流
zuc.zucEncrypt(key, iv, msg, counter);             // EEA3；同 (key, iv, counter) 只允许一次
zuc.zucDecrypt(key, iv, ct, counter);              // 解密（豁免复用保护）

const macIv = zuc.zucEia3Iv(count, bearer, direction);
bytesToHex(zuc.zucMac(key, macIv, msg));           // → 4 字节标签`,
      keyLabel: '密钥 key',
      keyHint: '16 字节 hex',
      ivLabel: '初始向量 iv',
      ivHint: '16 字节 hex',
      msgLabel: '消息',
      msgHint: 'EEA3 的明文 / EIA3 的受保护消息',
      encLabel: '消息编码',
      counterLabel: 'EEA3 counter',
      counterHint: (c: number) => `当前 ${c}`,
      countLabel: 'EIA3 COUNT',
      countHint: '32 位',
      bearerLabel: 'BEARER',
      bearerHint: '0..31',
      dirLabel: 'DIRECTION',
      dirHint: '0 或 1',
      keystreamKey: 'zucKeystream(key, iv, 16)',
      ctKey: 'zucEncrypt() → EEA3 密文',
      ptKey: 'zucDecrypt() → 还原（hex / 文本）',
      macKey: 'zucMac(key, zucEia3Iv(...), msg) → 32 位标签',
    },
  },

  en: {
    frame: { run: 'Run', running: 'Running…', src: 'Equivalent code' },
    sm3: {
      title: 'SM3 hash & HMAC-SM3',
      desc: 'Clicking Run loads sm3.wasm and actually computes hash and hmac over the message above.',
      code: `import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();          // warm up the wasm once (async)
sm3.hash('abc');                   // → 32-byte digest as hex
sm3.hmac(key, 'abc');              // → 32-byte HMAC as hex`,
      msgLabel: 'Message',
      msgHint: 'any length (empty allowed)',
      msgEncLabel: 'Message encoding',
      keyLabel: 'HMAC key',
      keyHint: '16-byte hex',
      keyEncLabel: 'Key encoding',
      hashKey: 'sm3.hash(msg)',
      hmacKey: 'sm3.hmac(key, msg)',
    },
    sm4: {
      title: 'SM4 encryption (ECB / CBC / CTR / CFB / OFB / GCM)',
      desc: 'Pick a mode and direction, set the key, then run. ECB does no padding, so the plaintext must be a multiple of 16 bytes; CBC adds PKCS#7; GCM is AEAD and also returns an authentication tag.',
      code: `import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
sm4.encryptCBC(key, iv, 'abc');                    // any length, PKCS#7 padded internally
sm4.encryptCTR(key, iv, 'abc');                    // stream mode, same as decryptCTR
const { ct, tag } = sm4.encryptGCM(key, iv, 'abc', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);             // throws DecryptionError on tampering`,
      modeLabel: 'Mode',
      dirLabel: 'Direction',
      dirEncrypt: 'Encrypt',
      dirDecrypt: 'Decrypt',
      keyLabel: 'key',
      keyHint: '16-byte hex',
      ivLabel: 'iv',
      ivHint: '16-byte hex (GCM usually 12)',
      inputLabel: 'Input',
      inputHint: 'plaintext when encrypting, ciphertext when decrypting',
      encLabel: 'Input encoding',
      aadLabel: 'Additional authenticated data (aad)',
      aadHint: 'may be empty',
      tagLabel: 'Authentication tag',
      tagHint: '16-byte hex, produced by encryptGCM',
      randomLabel: 'Random key / iv',
      outKey: (mode: string, dir: string) => `${mode} · ${dir} output (hex)`,
      tagKey: 'tag (GCM authentication tag)',
      utf8Key: 'Decoded as UTF-8',
    },
    sm2: {
      title: 'SM2 key pair, sign/verify, encrypt/decrypt',
      desc: 'One run walks the whole path: generate a key pair (first time) → SM3withSM2 signature → verify → encrypt → decrypt, plus one KEM + SM4-GCM hybrid encryption. Keys are PKCS#8 / SPKI PEM, the same format OpenSSL and GmSSL read.',
      code: `import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');       // SM3withSM2 by default, r||s as hex
sm2.verify(publicKeyPem, 'abc', sig);             // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');      // C1C3C2 by default
sm2.decrypt(privateKeyPem, ct);                   // ciphertext order is auto-detected

const sealed = sm2.hybridEncrypt(publicKeyPem, 'abc');  // KEM + SM4-GCM
sm2.hybridDecrypt(privateKeyPem, sealed);              // → '616263'`,
      regenLabel: 'Regenerate key pair',
      formatLabel: 'Ciphertext component order',
      msgLabel: 'Message',
      msgHint: 'UTF-8 encoded before signing / encrypting',
      privLabel: 'Private key (PKCS#8 PEM)',
      pubLabel: 'Public key (SPKI PEM)',
      sigKey: 'sm2.sign() → signature r‖s',
      verifyKey: 'sm2.verify()',
      ctKey: (fmt: string) => `sm2.encrypt() → ciphertext (${fmt})`,
      ptKey: 'sm2.decrypt() → plaintext',
      hybridKey: 'sm2.hybridEncrypt() → sealed (KEM + SM4-GCM)',
      hybridPtKey: 'sm2.hybridDecrypt() → plaintext',
      yes: 'true (verified)',
      no: 'false (verification failed)',
    },
    sm9: {
      title: 'SM9 identity-based: sign / encrypt / KEM',
      desc: 'The first run also generates two master key pairs (one for signing, one for encryption, ~4 ms), then exercises sign→verify, encrypt→decrypt, KEM encapsulate→decapsulate and one KEM + SM4-GCM hybrid encryption. The identity id *is* the public key — there is no certificate chain.',
      code: `import { sm9 } from 'sm-crypto-wasm';

const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });              // purpose defaults to 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', 'abc');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', 'abc');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);

const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);      // === key`,
      idLabel: 'Identity id',
      idHint: 'this *is* the public key; changing it regenerates the key pairs',
      msgLabel: 'Message',
      msgHint: 'UTF-8 encoded',
      klenLabel: 'KEM session key length (bytes)',
      klenHint: 'klen, defaults to 32',
      showKeys: "Show the master keys generated by this run (PEM)",
      signKey: 'sm9.sign() → h‖Sx‖Sy',
      verifyKey: 'sm9.verify()',
      ctKey: (bytes: number) => `sm9.encrypt() → ciphertext (${bytes} bytes)`,
      ptKey: 'sm9.decrypt() → plaintext',
      kemKey: 'sm9.kemEncrypt() → session key K',
      kemCheckKey: 'sm9.kemDecrypt() → does the unwrapped K match?',
      hybridKey: 'sm9.hybridEncrypt() → sealed (KEM + SM4-GCM)',
      hybridPtKey: 'sm9.hybridDecrypt() → plaintext',
      yes: 'true (verified)',
      no: 'false (verification failed)',
      match: 'match ✓',
      mismatch: 'mismatch ✗',
    },
    zuc: {
      title: 'ZUC EEA3 confidentiality + EIA3 integrity',
      desc: 'The same keystream drives EEA3 encryption/decryption and the 32-bit EIA3 MAC. Every run bumps the counter — reusing one (key, iv, counter) for encryption is a confidentiality failure, and the library refuses it outright.',
      code: `import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
zuc.zucKeystream(key, iv, 16);                     // → Uint8Array keystream
zuc.zucEncrypt(key, iv, msg, counter);             // EEA3; one (key, iv, counter) is allowed once
zuc.zucDecrypt(key, iv, ct, counter);              // decryption (reuse guard exempt)

const macIv = zuc.zucEia3Iv(count, bearer, direction);
bytesToHex(zuc.zucMac(key, macIv, msg));           // → 4-byte tag`,
      keyLabel: 'key',
      keyHint: '16-byte hex',
      ivLabel: 'iv',
      ivHint: '16-byte hex',
      msgLabel: 'Message',
      msgHint: 'EEA3 plaintext / EIA3 protected message',
      encLabel: 'Message encoding',
      counterLabel: 'EEA3 counter',
      counterHint: (c: number) => `currently ${c}`,
      countLabel: 'EIA3 COUNT',
      countHint: '32-bit',
      bearerLabel: 'BEARER',
      bearerHint: '0..31',
      dirLabel: 'DIRECTION',
      dirHint: '0 or 1',
      keystreamKey: 'zucKeystream(key, iv, 16)',
      ctKey: 'zucEncrypt() → EEA3 ciphertext',
      ptKey: 'zucDecrypt() → recovered (hex / text)',
      macKey: 'zucMac(key, zucEia3Iv(...), msg) → 32-bit tag',
    },
  },

  ru: {
    frame: { run: 'Запустить', running: 'Идёт выполнение…', src: 'Эквивалентный код' },
    sm3: {
      title: 'SM3: хеш и HMAC-SM3',
      desc: 'Нажатие «Запустить» загружает sm3.wasm и реально считает hash и hmac по указанному выше сообщению.',
      code: `import { sm3 } from 'sm-crypto-wasm';

await sm3.ensureLoaded();          // один раз прогреваем wasm (асинхронно)
sm3.hash('abc');                   // → 32-байтный хеш в hex
sm3.hmac(key, 'abc');              // → 32-байтный HMAC в hex`,
      msgLabel: 'Сообщение',
      msgHint: 'любая длина (пустое допустимо)',
      msgEncLabel: 'Кодировка сообщения',
      keyLabel: 'Ключ HMAC',
      keyHint: '16 байт в hex',
      keyEncLabel: 'Кодировка ключа',
      hashKey: 'sm3.hash(msg)',
      hmacKey: 'sm3.hmac(key, msg)',
    },
    sm4: {
      title: 'SM4: шифрование (ECB / CBC / CTR / CFB / OFB / GCM)',
      desc: 'Выберите режим и направление, задайте ключ и запустите. ECB не выравнивает, поэтому открытый текст должен быть кратен 16 байтам; CBC добавляет PKCS#7; GCM — это AEAD и дополнительно возвращает тег аутентификации.',
      code: `import { sm4 } from 'sm-crypto-wasm';

await sm4.ensureLoaded();
sm4.encryptCBC(key, iv, 'abc');                    // любая длина, внутри PKCS#7
sm4.encryptCTR(key, iv, 'abc');                    // потоковый режим, то же, что decryptCTR
const { ct, tag } = sm4.encryptGCM(key, iv, 'abc', aad);
sm4.decryptGCM(key, iv, ct, tag, aad);             // при подмене — DecryptionError`,
      modeLabel: 'Режим',
      dirLabel: 'Направление',
      dirEncrypt: 'Шифрование',
      dirDecrypt: 'Расшифрование',
      keyLabel: 'ключ',
      keyHint: '16 байт в hex',
      ivLabel: 'iv',
      ivHint: '16 байт в hex (для GCM обычно 12)',
      inputLabel: 'Вход',
      inputHint: 'открытый текст при шифровании, шифротекст при расшифровании',
      encLabel: 'Кодировка входа',
      aadLabel: 'Дополнительные аутентифицируемые данные (aad)',
      aadHint: 'можно оставить пустым',
      tagLabel: 'Тег аутентификации',
      tagHint: '16 байт в hex, выдаётся encryptGCM',
      randomLabel: 'Случайные key / iv',
      outKey: (mode: string, dir: string) => `${mode} · ${dir}: результат (hex)`,
      tagKey: 'tag (тег аутентификации GCM)',
      utf8Key: 'Восстановлено как UTF-8',
    },
    sm2: {
      title: 'SM2: ключевая пара, подпись/проверка, шифрование/расшифрование',
      desc: 'Один запуск проходит весь путь: генерация ключевой пары (при первом запуске) → подпись SM3withSM2 → проверка → шифрование → расшифрование, плюс гибридное шифрование KEM + SM4-GCM. Ключи — PKCS#8 / SPKI PEM, тот же формат читают OpenSSL и GmSSL.',
      code: `import { sm2 } from 'sm-crypto-wasm';

const { privateKeyPem, publicKeyPem } = await sm2.generateKeyPair();

const sig = sm2.sign(privateKeyPem, 'abc');       // по умолчанию SM3withSM2, r||s в hex
sm2.verify(publicKeyPem, 'abc', sig);             // → true

const ct = sm2.encrypt(publicKeyPem, 'abc');      // по умолчанию C1C3C2
sm2.decrypt(privateKeyPem, ct);                   // порядок компонент определяется автоматически

const sealed = sm2.hybridEncrypt(publicKeyPem, 'abc');  // KEM + SM4-GCM
sm2.hybridDecrypt(privateKeyPem, sealed);              // → '616263'`,
      regenLabel: 'Сгенерировать ключевую пару заново',
      formatLabel: 'Порядок компонент шифротекста',
      msgLabel: 'Сообщение',
      msgHint: 'кодируется в UTF-8 перед подписью / шифрованием',
      privLabel: 'Приватный ключ (PKCS#8 PEM)',
      pubLabel: 'Открытый ключ (SPKI PEM)',
      sigKey: 'sm2.sign() → подпись r‖s',
      verifyKey: 'sm2.verify()',
      ctKey: (fmt: string) => `sm2.encrypt() → шифротекст (${fmt})`,
      ptKey: 'sm2.decrypt() → открытый текст',
      hybridKey: 'sm2.hybridEncrypt() → sealed (KEM + SM4-GCM)',
      hybridPtKey: 'sm2.hybridDecrypt() → открытый текст',
      yes: 'true (проверка пройдена)',
      no: 'false (проверка не пройдена)',
    },
    sm9: {
      title: 'SM9: идентификационная криптография — подпись / шифрование / KEM',
      desc: 'Первый запуск дополнительно создаёт две главные ключевые пары (для подписи и для шифрования, ~4 мс), затем выполняются подпись→проверка, шифрование→расшифрование, KEM инкапсуляция→декапсуляция и одно гибридное шифрование KEM + SM4-GCM. Идентификатор id *и есть* открытый ключ — цепочки сертификатов нет.',
      code: `import { sm9 } from 'sm-crypto-wasm';

const signKp = await sm9.generateKeyPair({ id: 'alice@foo.com' });              // purpose по умолчанию 'sign'
const encKp  = await sm9.generateKeyPair({ id: 'alice@foo.com', purpose: 'enc' });

const sig = sm9.sign(signKp.masterPrivatePem, 'alice@foo.com', 'abc');
sm9.verify(signKp.masterPublicPem, 'alice@foo.com', 'abc', sig);

const ct = sm9.encrypt(encKp.masterPublicPem, 'alice@foo.com', 'abc');
sm9.decrypt(encKp.masterPrivatePem, 'alice@foo.com', ct);

const { key, encapsulation } = sm9.kemEncrypt(encKp.masterPrivatePem, 'alice@foo.com', 32);
sm9.kemDecrypt(encKp.masterPrivatePem, 'alice@foo.com', encapsulation, 32);      // === key`,
      idLabel: 'Идентификатор id',
      idHint: 'это и есть открытый ключ; смена пересоздаёт ключевые пары',
      msgLabel: 'Сообщение',
      msgHint: 'кодируется в UTF-8',
      klenLabel: 'Длина сессионного ключа KEM (байт)',
      klenHint: 'klen, по умолчанию 32',
      showKeys: 'Показать главные ключи, созданные в этом запуске (PEM)',
      signKey: 'sm9.sign() → h‖Sx‖Sy',
      verifyKey: 'sm9.verify()',
      ctKey: (bytes: number) => `sm9.encrypt() → шифротекст (${bytes} байт)`,
      ptKey: 'sm9.decrypt() → открытый текст',
      kemKey: 'sm9.kemEncrypt() → сессионный ключ K',
      kemCheckKey: 'sm9.kemDecrypt() → совпадает ли декапсулированный K?',
      hybridKey: 'sm9.hybridEncrypt() → sealed (KEM + SM4-GCM)',
      hybridPtKey: 'sm9.hybridDecrypt() → открытый текст',
      yes: 'true (проверка пройдена)',
      no: 'false (проверка не пройдена)',
      match: 'совпадает ✓',
      mismatch: 'не совпадает ✗',
    },
    zuc: {
      title: 'ZUC: конфиденциальность EEA3 + целостность EIA3',
      desc: 'Один и тот же поток ключей обслуживает шифрование/расшифрование EEA3 и 32-битный MAC EIA3. Каждый запуск увеличивает counter — повторное использование одной тройки (key, iv, counter) для шифрования это провал конфиденциальности, и библиотека отказывает явно.',
      code: `import { zuc, bytesToHex } from 'sm-crypto-wasm';

await zuc.ensureLoaded();
zuc.zucKeystream(key, iv, 16);                     // → Uint8Array поток ключей
zuc.zucEncrypt(key, iv, msg, counter);             // EEA3; одна тройка (key, iv, counter) — один раз
zuc.zucDecrypt(key, iv, ct, counter);              // расшифрование (защита от повтора не применяется)

const macIv = zuc.zucEia3Iv(count, bearer, direction);
bytesToHex(zuc.zucMac(key, macIv, msg));           // → тег из 4 байт`,
      keyLabel: 'ключ',
      keyHint: '16 байт в hex',
      ivLabel: 'iv',
      ivHint: '16 байт в hex',
      msgLabel: 'Сообщение',
      msgHint: 'открытый текст EEA3 / защищаемое сообщение EIA3',
      encLabel: 'Кодировка сообщения',
      counterLabel: 'EEA3 counter',
      counterHint: (c: number) => `сейчас ${c}`,
      countLabel: 'EIA3 COUNT',
      countHint: '32 бита',
      bearerLabel: 'BEARER',
      bearerHint: '0..31',
      dirLabel: 'DIRECTION',
      dirHint: '0 или 1',
      keystreamKey: 'zucKeystream(key, iv, 16)',
      ctKey: 'zucEncrypt() → шифротекст EEA3',
      ptKey: 'zucDecrypt() → восстановлено (hex / текст)',
      macKey: 'zucMac(key, zucEia3Iv(...), msg) → тег 32 бита',
    },
  },
} as const;

/** 当前语言对应的 Playground 文案。 */
export function usePgText() {
  const { lang } = useData();
  return computed(() => TEXT[normalizeLang(lang.value)]);
}
