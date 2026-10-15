<script setup lang="ts">
import { ref } from 'vue';
import { sm3 } from 'sm-crypto-wasm';
import PgField from './PgField.vue';
import PlaygroundFrame from './PlaygroundFrame.vue';
import { type TextEncoding, toInput } from './pg-input';
import { usePgText } from './pg-i18n';

const ENCODINGS: TextEncoding[] = ['utf8', 'hex', 'base64'];

const pgText = usePgText();
const T = pgText;

const message = ref('abc');
const messageEnc = ref<TextEncoding>('utf8');
const hmacKey = ref('00112233445566778899aabbccddeeff');
const hmacKeyEnc = ref<TextEncoding>('hex');

const hashOut = ref('');
const hmacOut = ref('');

async function run() {
  await sm3.ensureLoaded();
  const msg = toInput(message.value, messageEnc.value);
  hashOut.value = sm3.hash(msg);
  hmacOut.value = sm3.hmac(toInput(hmacKey.value, hmacKeyEnc.value), msg);
}
</script>

<template>
  <PlaygroundFrame
    :title="T.sm3.title"
    :description="T.sm3.desc"
    :run="run"
    :code="T.sm3.code"
  >
    <PgField :label="T.sm3.msgLabel" :hint="T.sm3.msgHint">
      <textarea v-model="message" rows="3" spellcheck="false" />
    </PgField>

    <div class="pgf__row">
      <PgField :label="T.sm3.msgEncLabel">
        <select v-model="messageEnc">
          <option v-for="e in ENCODINGS" :key="e" :value="e">{{ e }}</option>
        </select>
      </PgField>
      <PgField :label="T.sm3.keyLabel" :hint="T.sm3.keyHint">
        <input v-model="hmacKey" spellcheck="false" />
      </PgField>
      <PgField :label="T.sm3.keyEncLabel">
        <select v-model="hmacKeyEnc">
          <option v-for="e in ENCODINGS" :key="e" :value="e">{{ e }}</option>
        </select>
      </PgField>
    </div>

    <template #result>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm3.hashKey }}</span>
        <span class="pgr__v">{{ hashOut || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm3.hmacKey }}</span>
        <span class="pgr__v">{{ hmacOut || '—' }}</span>
      </div>
    </template>
  </PlaygroundFrame>
</template>
