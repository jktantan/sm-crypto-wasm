<script setup lang="ts">
import { ref } from 'vue';
import { sm2 } from 'sm-crypto-wasm';
import PgField from './PgField.vue';
import PlaygroundFrame from './PlaygroundFrame.vue';
import { hexToText } from './pg-input';
import { usePgText } from './pg-i18n';

const T = usePgText();

const privateKeyPem = ref('');
const publicKeyPem = ref('');
const message = ref('abc');

const signature = ref('');
const verified = ref<boolean | null>(null);
const ciphertext = ref('');
const plaintext = ref('');
const cipherFormat = ref<'C1C3C2' | 'C1C2C3'>('C1C3C2');

async function generateKeys() {
  const kp = await sm2.generateKeyPair();
  privateKeyPem.value = kp.privateKeyPem;
  publicKeyPem.value = kp.publicKeyPem;
  signature.value = '';
  ciphertext.value = '';
  plaintext.value = '';
  verified.value = null;
}

async function run() {
  await sm2.ensureLoaded();
  if (privateKeyPem.value.trim() === '') await generateKeys();

  const msg = new TextEncoder().encode(message.value);
  signature.value = sm2.sign(privateKeyPem.value, msg);
  verified.value = sm2.verify(publicKeyPem.value, msg, signature.value);
  ciphertext.value = sm2.encrypt(publicKeyPem.value, msg, { outputFormat: cipherFormat.value });
  plaintext.value = sm2.decrypt(privateKeyPem.value, ciphertext.value);
}
</script>

<template>
  <PlaygroundFrame
    :title="T.sm2.title"
    :description="T.sm2.desc"
    :run="run"
    :code="T.sm2.code"
  >
    <div class="pgf__row">
      <button
        type="button"
        style="justify-self: start; font-size: 12px; padding: 6px 14px; cursor: pointer"
        @click="generateKeys"
      >
        {{ T.sm2.regenLabel }}
      </button>
      <PgField class="pgf--auto" :label="T.sm2.formatLabel">
        <select v-model="cipherFormat">
          <option value="C1C3C2">C1C3C2 (default)</option>
          <option value="C1C2C3">C1C2C3</option>
        </select>
      </PgField>
    </div>

    <PgField :label="T.sm2.msgLabel" :hint="T.sm2.msgHint">
      <input v-model="message" spellcheck="false" />
    </PgField>

    <PgField :label="T.sm2.privLabel">
      <textarea v-model="privateKeyPem" rows="4" spellcheck="false" />
    </PgField>

    <PgField :label="T.sm2.pubLabel">
      <textarea v-model="publicKeyPem" rows="3" spellcheck="false" />
    </PgField>

    <template #result>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm2.sigKey }}</span>
        <span class="pgr__v">{{ signature || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm2.verifyKey }}</span>
        <span class="pgr__v" :class="verified === null ? '' : verified ? 'pgr__v--ok' : 'pgr__v--bad'">
          {{ verified === null ? '—' : verified ? T.sm2.yes : T.sm2.no }}
        </span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm2.ctKey(cipherFormat) }}</span>
        <span class="pgr__v">{{ ciphertext || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm2.ptKey }}</span>
        <span class="pgr__v">{{ plaintext ? `${plaintext}（${hexToText(plaintext)}）` : '—' }}</span>
      </div>
    </template>
  </PlaygroundFrame>
</template>
