<script setup lang="ts">
import { computed, ref } from 'vue';
import { sm4 } from 'sm-crypto-wasm';
import PgField from './PgField.vue';
import PlaygroundFrame from './PlaygroundFrame.vue';
import { type TextEncoding, hexToText, randomHex, toInput } from './pg-input';
import { usePgText } from './pg-i18n';

type Mode = 'ECB' | 'CBC' | 'CTR' | 'CFB' | 'OFB' | 'GCM';
type Direction = 'encrypt' | 'decrypt';

const MODES: Mode[] = ['ECB', 'CBC', 'CTR', 'CFB', 'OFB', 'GCM'];
const ENCODINGS: TextEncoding[] = ['utf8', 'hex', 'base64'];

const T = usePgText();

const mode = ref<Mode>('CBC');
const direction = ref<Direction>('encrypt');
const key = ref('0123456789abcdeffedcba9876543210');
const iv = ref('000102030405060708090a0b0c0d0e0f');
const message = ref('abc');
const messageEnc = ref<TextEncoding>('utf8');
const aad = ref('aabbccdd');
/** GCM 解密时需要，值来自上一次加密的 tag。 */
const tagIn = ref('');

const out = ref('');
const tagOut = ref('');

const needIv = computed(() => mode.value !== 'ECB');
const needAad = computed(() => mode.value === 'GCM');
const needTag = computed(() => mode.value === 'GCM' && direction.value === 'decrypt');
const dirLabel = computed(() =>
  direction.value === 'encrypt' ? T.value.sm4.dirEncrypt : T.value.sm4.dirDecrypt,
);

function randomize() {
  key.value = randomHex(16);
  iv.value = randomHex(16);
}

async function run() {
  await sm4.ensureLoaded();
  const k = key.value.trim();
  const v = iv.value.trim();
  const input = toInput(message.value, messageEnc.value);
  out.value = '';
  tagOut.value = '';

  if (direction.value === 'encrypt') {
    switch (mode.value) {
      case 'ECB':
        out.value = sm4.encryptECB(k, input);
        break;
      case 'CBC':
        out.value = sm4.encryptCBC(k, v, input);
        break;
      case 'CTR':
        out.value = sm4.encryptCTR(k, v, input);
        break;
      case 'CFB':
        out.value = sm4.encryptCFB(k, v, input);
        break;
      case 'OFB':
        out.value = sm4.encryptOFB(k, v, input);
        break;
      case 'GCM': {
        const r = sm4.encryptGCM(k, v, input, aad.value.trim());
        out.value = r.ct;
        tagOut.value = r.tag;
        tagIn.value = r.tag; // 方便紧接着切到「解密」再跑一次
        break;
      }
    }
    return;
  }

  switch (mode.value) {
    case 'ECB':
      out.value = sm4.decryptECB(k, input);
      break;
    case 'CBC':
      out.value = sm4.decryptCBC(k, v, input);
      break;
    case 'CTR':
      out.value = sm4.decryptCTR(k, v, input);
      break;
    case 'CFB':
      out.value = sm4.decryptCFB(k, v, input);
      break;
    case 'OFB':
      out.value = sm4.decryptOFB(k, v, input);
      break;
    case 'GCM':
      out.value = sm4.decryptGCM(k, v, input, tagIn.value.trim(), aad.value.trim());
      break;
  }
}
</script>

<template>
  <PlaygroundFrame
    :title="T.sm4.title"
    :description="T.sm4.desc"
    :run="run"
    :code="T.sm4.code"
  >
    <div class="pgf__row">
      <PgField class="pgf--auto" :label="T.sm4.modeLabel">
        <select v-model="mode">
          <option v-for="m in MODES" :key="m" :value="m">{{ m }}</option>
        </select>
      </PgField>
      <PgField class="pgf--auto" :label="T.sm4.dirLabel">
        <select v-model="direction">
          <option value="encrypt">{{ T.sm4.dirEncrypt }}</option>
          <option value="decrypt">{{ T.sm4.dirDecrypt }}</option>
        </select>
      </PgField>
    </div>

    <PgField :label="T.sm4.keyLabel" :hint="T.sm4.keyHint">
      <input v-model="key" spellcheck="false" />
    </PgField>

    <PgField v-if="needIv" :label="T.sm4.ivLabel" :hint="T.sm4.ivHint">
      <input v-model="iv" spellcheck="false" />
    </PgField>

    <PgField :label="T.sm4.inputLabel" :hint="T.sm4.inputHint">
      <textarea v-model="message" rows="3" spellcheck="false" />
    </PgField>

    <div class="pgf__row">
      <PgField class="pgf--auto" :label="T.sm4.encLabel">
        <select v-model="messageEnc">
          <option v-for="e in ENCODINGS" :key="e" :value="e">{{ e }}</option>
        </select>
      </PgField>
      <PgField v-if="needAad" :label="T.sm4.aadLabel" :hint="T.sm4.aadHint">
        <input v-model="aad" spellcheck="false" />
      </PgField>
    </div>

    <PgField v-if="needTag" :label="T.sm4.tagLabel" :hint="T.sm4.tagHint">
      <input v-model="tagIn" spellcheck="false" />
    </PgField>

    <button
      class="pg__genbtn"
      type="button"
      style="justify-self: start; font-size: 12px"
      @click="randomize"
    >
      {{ T.sm4.randomLabel }}
    </button>

    <template #result>
      <div class="pgr">
        <span class="pgr__k">{{ T.sm4.outKey(mode, dirLabel) }}</span>
        <span class="pgr__v">{{ out || '—' }}</span>
      </div>
      <div v-if="tagOut" class="pgr">
        <span class="pgr__k">{{ T.sm4.tagKey }}</span>
        <span class="pgr__v">{{ tagOut }}</span>
      </div>
      <div v-if="direction === 'decrypt' && out" class="pgr">
        <span class="pgr__k">{{ T.sm4.utf8Key }}</span>
        <span class="pgr__v">{{ hexToText(out) }}</span>
      </div>
    </template>
  </PlaygroundFrame>
</template>
