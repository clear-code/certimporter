# �g����

�ؖ����t�@�C���� %AppDir%/defaults/ �ȉ��iWindows�ł���΁uC:\Program Files (x86)\Mozilla Firefox\defaults�v�Ȃǁj�ɒu���ĉ������B
Firefox���ċN������ƁA�ؖ����������I�ɃC���|�[�g����܂��B

���̃A�h�I���͖@�l���p��O��ɊJ������Ă��܂��B

## �Ή����Ă���ؖ����t�@�C���̎��

DER X509�`������ϊ����ꂽPEM�`���̃t�@�C���ɂ̂ݑΉ����Ă��܂��B
�t�@�C���̊g���q�́u.crt�v�u.cer�v�u.pem�v�̂����ꂩ�ł���K�v������܂��B
�T���v���̏ؖ����̓��|�W�g���́udoc/*.pem�v���Q�Ƃ��ĉ������B

�ؖ����̎�ނ͎������ʂ���܂����A�ݒ�ŏ㏑�����鎖���ł��܂��B
�T���v���̐ݒ�̓��|�W�g���́udoc/sample.js�v���Q�Ƃ��ĉ������B

## �Z�L�����e�B��O

�Z�L�����e�B��O�̐ݒ�t�@�C�����u�i�ؖ����t�@�C���̖��O�j.override�v�Ƃ������O�ŏؖ����t�@�C���Ɠ����ʒu�ɒu���Ă����ƁA�t�@�C�����Œ�`����Ă���Z�L�����e�B��O�������I�ɓK�p���܂��B
�T���v���̐ݒ�̓��|�W�g���́udoc/newcert.pem.override�v���Q�Ƃ��ĉ������B

## �����Ă݂�

 1. ���𐮂���B
    1. �Â��o�[�W������certimporter���폜����B
    2. about:config���J���B
    3. "extensions.certimporter.certs.*.lastOverrideDate" �Ō�����S�Ă̍��ڂ����Z�b�g����B
    4. "extensions.certimporter.debug" �� "true" �ɐݒ肷��B
    5. �ؖ����}�l�[�W�����J���B
    6. �u�F�؋Ǐؖ����v�^�u��I������B
    7. �ȉ���2�̏ؖ������o�^����Ă�����A�폜����B
       * "!example" > "site.example.com"
       * "!example" > "example.com"
    8. �u�T�[�o�ؖ����v�^�u��I������B
    9. �ȉ���3�̗�O���o�^����Ă�����A�폜����B
    10. Firefox���ċN������B
    11. �ؖ����}�l�[�W�����J���B
    12. �u�F�؋Ǐؖ����v�^�u�z���Ɉȉ��̂悤�ȍ��ڂ��Ȃ����Ƃ��m�F����B
        * "!example"
    13. �u�T�[�o�ؖ����v�^�u�z���Ɉȉ��̂悤�ȍ��ڂ��Ȃ����Ƃ��m�F����B
        * "(Unknown)" > "(NotStored)" > "(something).example.com:443"
 2. certimporter���C���X�g�[������B
 3. �ȉ���3�̃t�@�C�����AFirefox�̃C���X�g�[���f�B���N�g�����́udefaults�v�ȉ��ɒu���B
    * doc/cacert.pem
    * doc/newcert.pem
    * doc/newcert.pem.override
 4. Firefox���ċN������B
 5. �ؖ����}�l�[�W�����J���B
 6. �ȉ��̍��ڂ��F�؋Ǐؖ����Ƃ��ēo�^����Ă��邱�Ƃ��m�F����B
    * "!example" > "site.example.com"
    * "!example" > "example.com"
 7. �ȉ��̍��ڂ��T�[�o�ؖ����̗�O�Ƃ��ēo�^����Ă��邱�Ƃ��m�F����B
    * "(Unknown)" > "(NotStored)" > "site.example.com:443"
    * "(Unknown)" > "(NotStored)" > "foo.example.com:443"
    * "(Unknown)" > "(NotStored)" > "bar.example.com:443"

