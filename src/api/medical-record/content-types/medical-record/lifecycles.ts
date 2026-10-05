import { encrypt, decrypt } from '../../../../utils/crypto';

/**
 * Helper to decrypt sensitive clinical fields on a record object.
 */
function decryptRecord(record: any) {
  if (!record || typeof record !== 'object') return;
  if (record.diagnosis) {
    record.diagnosis = decrypt(record.diagnosis);
  }
  if (record.treatment) {
    record.treatment = decrypt(record.treatment);
  }
  if (record.prescription) {
    record.prescription = decrypt(record.prescription);
  }
}

export default {
  /**
   * Before saving to DB: Encrypt sensitive fields with AES-256-GCM.
   */
  beforeCreate(event: any) {
    const { data } = event.params;
    if (data) {
      if (data.diagnosis) {
        data.diagnosis = encrypt(data.diagnosis);
      }
      if (data.treatment) {
        data.treatment = encrypt(data.treatment);
      }
      if (data.prescription) {
        data.prescription = encrypt(data.prescription);
      }
    }
  },

  /**
   * Before updating DB: Encrypt sensitive fields with AES-256-GCM.
   */
  beforeUpdate(event: any) {
    const { data } = event.params;
    if (data) {
      if (data.diagnosis) {
        data.diagnosis = encrypt(data.diagnosis);
      }
      if (data.treatment) {
        data.treatment = encrypt(data.treatment);
      }
      if (data.prescription) {
        data.prescription = encrypt(data.prescription);
      }
    }
  },

  /**
   * After creating: Decrypt for response so the authorized client sees plaintext.
   */
  afterCreate(event: any) {
    decryptRecord(event.result);
  },

  /**
   * After updating: Decrypt for response.
   */
  afterUpdate(event: any) {
    decryptRecord(event.result);
  },

  /**
   * After fetching single entry: Decrypt sensitive fields.
   */
  afterFindOne(event: any) {
    decryptRecord(event.result);
  },

  /**
   * After fetching multiple entries: Decrypt sensitive fields for each entry.
   */
  afterFindMany(event: any) {
    if (Array.isArray(event.result)) {
      event.result.forEach(decryptRecord);
    } else if (event.result) {
      decryptRecord(event.result);
    }
  },
};

