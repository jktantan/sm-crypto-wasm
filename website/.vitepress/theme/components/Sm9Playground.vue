<script setup lang="ts">
import { ref } from 'vue';
import { sm9 } from 'sm-crypto-wasm';
import PgField from './PgField.vue';
import PlaygroundFrame from './PlaygroundFrame.vue';
import { hexToText } from './pg-input';
import { usePgText } from './pg-i18n';

type KeyPair = Awaited<ReturnType<typeof sm9.generateKeyPair>>;

const T = usePgText();

const id = ref('alice@example.com');
const message = ref('abc');
const klen = ref(32);

const signKp = ref<KeyPair | null>(null);
const encKp = ref<KeyPair | null>(null);

const signature = ref('');
const verified = ref<boolean | null>(null);
const ciphertext = ref('');
const plaintext = ref('');
const kemKey = ref('');
const kemUnwrapped = ref('');

async function run() {
  await sm9.ensureLoaded();
  // 签名与加密是两套主密钥（purpose 区分），首次运行时各生成一次。
  if (signKp.value === null) {
    signKp.value = await sm9.generateKeyPair({ id: id.value, purpose: 'sign' });
  }
  if (encKp.value === null) {
    encKp.value = await sm9.generateKeyPair({ id: id.value, purpose: 'enc' });
  }

  const msg = new TextEncoder().encode(message.value);

  signature.value = sm9.sign(signKp.value.masterPrivatePem, id.value, msg);
  verified.value = sm9.verify(signKp.value.masterPublicPem, id.value, msg, signature.value);

  ciphertext.value = sm9.encrypt(encKp.value.masterPublicPem, id.value, msg);
  plaintext.value = sm9.decrypt(encKp.value.masterPrivatePem, id.value, ciphertext.value);

  const kem = sm9.kemEncrypt(encKp.value.masterPrivatePem, id.value, klen.value);
  kemKey.value = kem.key;
  kemUnwrapped.value = sm9.kemDecrypt(
    encKp.value.masterPrivatePem,
    id.value,
    kem.encapsulation,
    klen.value,
  );
}

function reset() {
  signKp.value = null;
  encKp.value = null;
  signature.value = '';
  ciphertext.value = '';
  plaintext.value = '';
  kemKey.value = '';
  kemUnwrapped.value = '';
  verified.value = null;
}
</script>

<template>
  <PlaygroundFrame
    :title="T.sm9.title"
    :description="T.sm9.desc"
    :run="run"
    :code="T.sm9.code"
  >
    <PgField :label="T.sm9.idLabel" :hint="T.sm9.idHint">
      <input v-model="id" spellcheck="false" @change="reset" />
    </PgField>

    <PgField :label="T.sm9.msgLabel" :hint="T.sm9.msgHint">
      <input v-model="message" spellcheck="false" />
    </PgField>

    <PgField class="pgf--auto" :label="T.sm9.klenLabel" :hint="T.sm9.klenHint">
      <input v-model.number="klen" type="number" min="1" max="64" />
    </PgField>

    <details v-if="signKp" style="font-size: 12px">
      <summary style="cursor: pointer">{{ T.sm9.showKeys }}</summary>
      <pre style="overflow-x: auto; white-space: pre-wrap">{{
        `${signKp.masterPublicPem}\n\n${encKp?.masterPublicPem ?? ''}`
      }}</pre>
    </details>

    <template #result>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.signKey }}</span>
        <span class="pgr__v">{{ signature || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.verifyKey }}</span>
        <span class="pgr__v" :class="verified === null ? '' : verified ? 'pgr__v--ok' : 'pgr__v--bad'">
          {{ verified === null ? '—' : verified ? T.sm9.yes : T.sm9.no }}
        </span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.ctKey(ciphertext ? ciphertext.length / 2 : 0) }}</span>
        <span class="pgr__v">{{ ciphertext || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.ptKey }}</span>
        <span class="pgr__v">{{ plaintext ? `${plaintext}（${hexToText(plaintext)}）` : '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.kemKey }}</span>
        <span class="pgr__v">{{ kemKey || '—' }}</span>
      </div>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm9.kemCheckKey }}</span>
        <span
          class="pgr__v"
          :class="kemUnwrapped === '' ? '' : kemUnwrapped === kemKey ? 'pgr__v--ok' : 'pgr__v--bad'"
        >
          {{ kemUnwrapped === '' ? '—' : kemUnwrapped === kemKey ? T.sm9.match : T.sm9.mismatch }}
        </span>
      </div>
    </template>
  </PlaygroundFrame>
</template>
