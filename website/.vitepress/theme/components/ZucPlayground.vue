<script setup lang="ts">
import { ref } from 'vue';
import { bytesToHex, zuc } from 'sm-crypto-wasm';
import PgField from './PgField.vue';
import PlaygroundFrame from './PlaygroundFrame.vue';
import { type TextEncoding, hexToText, toInput } from './pg-input';
import { usePgText } from './pg-i18n';

const ENCODINGS: TextEncoding[] = ['utf8', 'hex', 'base64'];

const T = usePgText();

const key = ref('000102030405060708090a0b0c0d0e0f');
const iv = ref('00000000000000000000000000000000');
const message = ref('abc');
const messageEnc = ref<TextEncoding>('utf8');
const count = ref(0x66035492);
const bearer = ref(15);
const direction = ref(0);
const counter = ref(0);

const keystream = ref('');
const ciphertext = ref('');
const plaintext = ref('');
const mac = ref('');

async function run() {
  await zuc.ensureLoaded();
  const k = key.value.trim();
  const v = iv.value.trim();
  const msg = toInput(message.value, messageEnc.value);

  // 同一 (key, iv, counter) 只允许加密一次 —— 每次运行换一个 counter，
  // 这样重复点「运行」不会撞上复用保护（撞上会抛 InvalidKeyError）。
  const c = counter.value;
  counter.value += 1;

  keystream.value = bytesToHex(zuc.zucKeystream(k, v, 16));
  const ct = zuc.zucEncrypt(k, v, msg, c);
  ciphertext.value = bytesToHex(ct);
  plaintext.value = bytesToHex(zuc.zucDecrypt(k, v, ct, c));
  mac.value = bytesToHex(
    zuc.zucMac(k, zuc.zucEia3Iv(count.value, bearer.value, direction.value), msg),
  );
}
</script>

<template>
  <PlaygroundFrame
    :title="T.zuc.title"
    :description="T.zuc.desc"
    :run="run"
    :code="T.zuc.code"
  >
    <div class="pgf__row">
      <PgField :label="T.zuc.keyLabel" :hint="T.zuc.keyHint">
        <input v-model="key" spellcheck="false" />
      </PgField>
      <PgField :label="T.zuc.ivLabel" :hint="T.zuc.ivHint">
        <input v-model="iv" spellcheck="false" />
      </PgField>
    </div>

    <PgField :label="T.zuc.msgLabel" :hint="T.zuc.msgHint">
      <textarea v-model="message" rows="2" spellcheck="false" />
    </PgField>

    <div class="pgf__row">
      <PgField class="pgf--auto" :label="T.zuc.encLabel">
        <select v-model="messageEnc">
          <option v-for="e in ENCODINGS" :key="e" :value="e">{{ e }}</option>
        </select>
      </PgField>
      <PgField class="pgf--auto" :label="T.zuc.counterLabel" :hint="T.zuc.counterHint(counter)">
        <input :value="counter" disabled />
      </PgField>
      <PgField class="pgf--auto" :label="T.zuc.countLabel" :hint="T.zuc.countHint">
        <input v-model.number="count" type="number" />
      </PgField>
      <PgField class="pgf--auto" :label="T.zuc.bearerLabel" :hint="T.zuc.bearerHint">
        <input v-model.number="bearer" type="number" min="0" max="31" />
      </PgField>
      <PgField class="pgf--auto" :label="T.zuc.dirLabel" :hint="T.zuc.dirHint">
        <input v-model.number="direction" type="number" min="0" max="1" />
      </PgField>
    </div>

    <template #result>
      <div class="pgr">
        <span class="pgr__k">{{ T.zuc.keystreamKey }}</span>
        <span class="pgr__v">{{ keystream || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.zuc.ctKey }}</span>
        <span class="pgr__v">{{ ciphertext || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.zuc.ptKey }}</span>
        <span class="pgr__v">{{ plaintext ? `${plaintext}（${hexToText(plaintext)}）` : '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.zuc.macKey }}</span>
        <span class="pgr__v">{{ mac || '—' }}</span>
      </div>
    </template>
  </PlaygroundFrame>
</template>
