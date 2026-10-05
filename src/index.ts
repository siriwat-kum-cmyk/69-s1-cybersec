import type { Core } from '@strapi/strapi';

export default {
  /**
   * An asynchronous register function that runs before
   * your application is initialized.
   */
  register(/* { strapi }: { strapi: Core.Strapi } */) {},

  /**
   * Bootstrap function to automatically configure RBAC roles and default medical personnel:
   * - Doctor Role: Full CRUD on Patients & MedicalRecords
   * - Nurse Role: Read-only on Patients & MedicalRecords
   * - Public Role: No permissions (403 Forbidden)
   */
  async bootstrap({ strapi }: { strapi: Core.Strapi }) {
    try {
      const roleService = strapi.plugin('users-permissions').service('role');
      const userService = strapi.plugin('users-permissions').service('user');

      const existingRoles = await strapi.db.query('plugin::users-permissions.role').findMany();

      // 1. Ensure Doctor Role exists
      let doctorRole = existingRoles.find((r: any) => r.type === 'doctor');
      if (!doctorRole) {
        await roleService.createRole({
          name: 'Doctor',
          description: 'Doctors with full CRUD access to Patients and Medical Records',
          type: 'doctor',
          permissions: {
            'api::patient': {
              controllers: {
                patient: {
                  find: { enabled: true },
                  findOne: { enabled: true },
                  create: { enabled: true },
                  update: { enabled: true },
                },
              },
            },
            'api::medical-record': {
              controllers: {
                'medical-record': {
                  find: { enabled: true },
                  findOne: { enabled: true },
                  create: { enabled: true },
                  update: { enabled: true },
                },
              },
            },
          },
        });
        doctorRole = await strapi.db.query('plugin::users-permissions.role').findOne({ where: { type: 'doctor' } });
      }

      // 2. Ensure Nurse Role exists (Read-Only)
      let nurseRole = existingRoles.find((r: any) => r.type === 'nurse');
      if (!nurseRole) {
        await roleService.createRole({
          name: 'Nurse',
          description: 'Nurses with Read-Only access to Patients and Medical Records',
          type: 'nurse',
          permissions: {
            'api::patient': {
              controllers: {
                patient: {
                  find: { enabled: true },
                  findOne: { enabled: true },
                  create: { enabled: false },
                  update: { enabled: false },
                },
              },
            },
            'api::medical-record': {
              controllers: {
                'medical-record': {
                  find: { enabled: true },
                  findOne: { enabled: true },
                  create: { enabled: false },
                  update: { enabled: false },
                },
              },
            },
          },
        });
        nurseRole = await strapi.db.query('plugin::users-permissions.role').findOne({ where: { type: 'nurse' } });
      }

      // 3. Ensure Doctor User exists (if configured in environment)
      if (doctorRole && process.env.DOCTOR_EMAIL && process.env.DOCTOR_PASSWORD) {
        const doctorEmail = process.env.DOCTOR_EMAIL;
        const doctorUsername = process.env.DOCTOR_USERNAME || doctorEmail.split('@')[0];
        const doctorPassword = process.env.DOCTOR_PASSWORD;

        const doctorUser = await strapi.db.query('plugin::users-permissions.user').findOne({
          where: { email: doctorEmail },
        });
        if (!doctorUser) {
          await userService.add({
            username: doctorUsername,
            email: doctorEmail,
            password: doctorPassword,
            provider: 'local',
            confirmed: true,
            blocked: false,
            role: doctorRole.id,
          });
        }
      }

      // 4. Ensure Nurse User exists (if configured in environment)
      if (nurseRole && process.env.NURSE_EMAIL && process.env.NURSE_PASSWORD) {
        const nurseEmail = process.env.NURSE_EMAIL;
        const nurseUsername = process.env.NURSE_USERNAME || nurseEmail.split('@')[0];
        const nursePassword = process.env.NURSE_PASSWORD;

        const nurseUser = await strapi.db.query('plugin::users-permissions.user').findOne({
          where: { email: nurseEmail },
        });
        if (!nurseUser) {
          await userService.add({
            username: nurseUsername,
            email: nurseEmail,
            password: nursePassword,
            provider: 'local',
            confirmed: true,
            blocked: false,
            role: nurseRole.id,
          });
        }
      }
    } catch (err) {
      strapi.log.error('Bootstrap RBAC configuration error:', err);
    }
  },
};
