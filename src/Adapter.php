<?php
declare(strict_types=1);

namespace KalkanCrypt;

use KalkanCrypt\Exception\AdapterException;

class Adapter{

    private static self|null $instance = null;
    const EXT_NAME = 'kalkancrypt';

    /**
     * Константы, определяющие способ хранения ключей/сертификатов (вид хранилища/носителя)
     */
    const KCST_PKCS12                       =   0x1;  //  Файловая система (небезопасный способ хранения ключей)
    const KCST_KZIDCARD                     =   0x2;  //  Удостоверение личности гражданина РК
    const KCST_KAZTOKEN                     =   0x4;
    const KCST_ETOKEN72K                    =   0x8;
    const KCST_JACARTA                      =   0x10;
    const KCST_X509CERT                     =   0x20;
    const KCST_AKEY                         =   0x40;

    /**
     * Константы, определяющие принадлежность сертификата.
     */
    const KC_CERT_CA                        =   0x201;
    const KC_CERT_INTERMEDIATE              =   0x202;
    const KC_CERT_USER                      =   0x204;

    /**
     * Константы, определяющие тип кодировки.
     */
    const KC_CERT_DER                       =   0x101;
    const KC_CERT_PEM                       =   0x102;
    const KC_CERT_B64                       =   0x104;
    /**
     * Константы, определяющие тип валидации
     */
    const KC_USE_NOTHING                    =   0x401; // Не делать проверок
    const KC_USE_CRL                        =   0x402; // Проверка сертификата по списку отозванных сертификатов
    const KC_USE_OCSP                       =   0x404; // Проверка сертификата посредством сервиса OCSP

    /**
     * Константы, определяющие значение поля/расширения в запросе/сертификате.
     */
    const KC_CERTPROP_ISSUER_COUNTRYNAME    =	0x801; //	Страна издателя
    const KC_CERTPROP_ISSUER_SOPN           =	0x802; //	Название штата или провинции издателя
    const KC_CERTPROP_ISSUER_LOCALITYNAME   =	0x803; //	Населённый пункт издателя
    const KC_CERTPROP_ISSUER_ORG_NAME       =	0x804; //	Наименование организации издателя
    const KC_CERTPROP_ISSUER_ORGUNIT_NAME   =	0x805; //	Название организационного подразделения издателя
    const KC_CERTPROP_ISSUER_COMMONNAME     =	0x806; //	Имя Фамилия издателя
    const KC_CERTPROP_SUBJECT_COUNTRYNAME   =	0x807; //	Страна субъекта
    const KC_CERTPROP_SUBJECT_SOPN          =	0x808; //	Название штата или провинции субъекта
    const KC_CERTPROP_SUBJECT_LOCALITYNAME  =	0x809; //	Населенный пункт субъекта
    const KC_CERTPROP_SUBJECT_COMMONNAME    =	0x80a; //	Общее имя субъекта
    const KC_CERTPROP_SUBJECT_GIVENNAME     =	0x80b; //	Имя субъекта
    const KC_CERTPROP_SUBJECT_SURNAME       =	0x80c; //	Фамилия субъекта
    const KC_CERTPROP_SUBJECT_SERIALNUMBER  =	0x80d; //	Серийный номер субъекта
    const KC_CERTPROP_SUBJECT_EMAIL         =	0x80e; //	e-mail субъекта
    const KC_CERTPROP_SUBJECT_ORG_NAME      =	0x80f; //	Наименование организации субъекта
    const KC_CERTPROP_SUBJECT_ORGUNIT_NAME  =	0x810; //	Название организационного подразделения субъекта
    const KC_CERTPROP_SUBJECT_BC            =	0x811; //	Бизнес категория субъекта
    const KC_CERTPROP_SUBJECT_DC            =	0x812; //	Доменный компонент субъекта
    const KC_CERTPROP_NOTBEFORE             =	0x813; //	Дата действителен с
    const KC_CERTPROP_NOTAFTER              =	0x814; //	Дата действителен по
    const KC_CERTPROP_KEY_USAGE             =	0x815; //	Использование ключа
    const KC_CERTPROP_EXT_KEY_USAGE         =	0x816; //	Расширенное использование ключа
    const KC_CERTPROP_AUTH_KEY_ID           =	0x817; //	Идентификатор ключа центра сертификации
    const KC_CERTPROP_SUBJ_KEY_ID           =	0x818; //	Идентификатор ключа субъекта
    const KC_CERTPROP_CERT_SN               =	0x819; //	Серийный номер серификата
    const KC_CERTPROP_ISSUER_DN             =	0x81a; //	Отличительное имя издателя
    const KC_CERTPROP_SUBJECT_DN            =	0x81b; //	Отличительное имя субъекта
    const KC_CERTPROP_SIGNATURE_ALG         =	0x81c; //	Алгоритм подписи
    const KC_CERTPROP_PUBKEY                = 	0x81d; //	Получение открытого ключа
    const KC_CERTPROP_POLICIES_ID           =	0x81e; //	Получение идентификатора политики сертификата
    const KC_CERTPROP_OCSP                  = 	0x81f; //	Получение URL-адреса OCSP
    const KC_CERTPROP_GET_CRL               =	0x820; //	Получение URL-адреса CRL
    const KC_CERTPROP_GET_DELTA_CRL         =	0x821; //	Получение URL-адреса delta CRL

    /**
     * Константы, определяющие дополнительные условия выполнения операций. Используется как параметр в функциях
     */
    const KC_SIGN_DRAFT                     =	0x00000001; //	Сырая подпись (draft sign)
    const KC_SIGN_CMS                       =	0x00000002; //	Подпись в формате CMS
    const KC_IN_PEM                         =	0x00000004; //	Входные данные в формате PEM
    const KC_IN_DER                         =	0x00000008; //	Входные данные в кодировке DER
    const KC_IN_BASE64                      =	0x00000010; //	Входные данные в кодировке BASE64
    const KC_IN2_BASE64                     =	0x00000020; //	Дополнительные входные данные в кодировке BASE64
    const KC_DETACHED_DATA                  =	0x00000040; //	Отсоединенная подпись
    const KC_WITH_CERT                      =	0x00000080; //	Вложить сертификат в подпись
    const KC_WITH_TIMESTAMP                 =	0x00000100; //	Добавить в подпись метку времени (не используется в текущей версии???)
    const KC_OUT_PEM                        =	0x00000200; //	Выходные данные в формате PEM
    const KC_OUT_DER                        =	0x00000400; //	Выходные данные в кодировке DER
    const KC_OUT_BASE64                     =	0x00000800; //	Выходные данные в кодировке BASE64
    const KC_PROXY_OFF                      =	0x00001000; //	Отключить использование прокси-сервера и стереть настройки.
    const KC_PROXY_ON                       =	0x00002000; //	Включить и установить настройки прокси-сервера (адрес и порт)
    const KC_PROXY_AUTH                     =	0x00004000; //	Прокси-сервер требует авторизацию (логин/пароль)
    const KC_IN_FILE                        =	0x00008000; //	Использовать, если параметр inData/outData содержит абсолютный путь к файлу.


    const KC_NOCHECKCERTTIME                =	0x00010000; //	Не проверять срок действия сертификата при построении цепочки до корневого (для проверки старых подписей с просроченным сертификатом)
    const KC_HASH_SHA256                    = 	0x00020000; //	Алгоритм хеширования sha256
    const KC_HASH_GOST95                    =	0x00040000; //	Алгоритм хеширования Gost34311_95
    const KC_GET_OCSP_RESPONSE              =	0x00080000; //	Вывести ответ от OCSP-сервиса



    private array $states;
    /**
     * @throws AdapterException
     */
    protected function __construct()
    {
        if (!extension_loaded(self::EXT_NAME)) {
            throw new AdapterException("Extension load failed!");
        }
        $this->call(
            KalkanCrypt_Init()
        );
    }

    public function __destruct()
    {
        $this->finalize();
    }

    public static function getInstance(): Adapter
    {
        if (!self::$instance instanceof self) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function destroy(): void
    {
        self::$instance = null;
    }

    /**
     * Загрузка ключей/сертификата из хранилища.
     *
     * @param int $storage тип хранилища
     * @param string $password пароль к хранилищу
     * @param string $container название хранилища (путь)
     * @param string $alias label (alias) сертификата
     * @return void
     * @throws AdapterException
     */
    public function loadKeyStore(int $storage, string $container, string $password, string $alias = ""): void
    {
        $this->call(
            KalkanCrypt_LoadKeyStore($storage, $password, $container, $alias)
        );
    }

    /**
     * @param int $prop_id
     * @param string $cert
     * @param bool $skip_fail
     * @return string|null
     * @throws AdapterException
     */
    public function getCertInfo(int $prop_id, string $cert, bool $skip_fail = true): ?string
    {
        $prop_value = "";
        try{
            $this->call(
                KalkanCrypt_X509CertificateGetInfo($prop_id, $cert, $prop_value)
            );
        } catch (AdapterException $e){
            return $skip_fail && $e->getCode() == Error::KCR_GETCERTPROPERR->value ? $prop_value : throw $e;
        }
        return $prop_value;
    }

    /**
     * @param int $encodeType
     * <br/> Adapter::KC_CERT_DER
     * <br/> Adapter::KC_CERT_PEM
     * <br/> Adapter::KC_CERT_B64
     * @param string $alias
     * @return string
     * @throws AdapterException
     */
    public function exportCertFromStore(string $alias = "", int $encodeType = 0): string
    {
        $outCert = "";
        $this->call(
            KalkanCrypt_X509ExportCertificateFromStore($alias, $encodeType, $outCert)
        );
        return $outCert;
    }

    /**
     * @param int $certType
     * <br/> Adapter::KC_CERT_CA
     * <br/> Adapter::KC_CERT_INTERMEDIATE
     * <br/> Adapter::KC_CERT_USER
     * @param string $filePath
     * @return void
     * @throws AdapterException
     */
    public function loadCertFromFile(int $certType, string $filePath): void
    {
        $this->call(
            KalkanCrypt_X509LoadCertificateFromFile($certType, $filePath)
        );
    }

    /**
     * @param string $cert
     * @param int $encodeType
     * <br/> Adapter::KC_CERT_DER
     * <br/> Adapter::KC_CERT_PEM
     * <br/> Adapter::KC_CERT_B64
     * @return void
     * @throws AdapterException
     */
    public function loadCertFromBuffer(string $cert, int $encodeType): void
    {
        $this->call(
            KalkanCrypt_X509LoadCertificateFromBuffer($cert, $encodeType)
        );
    }

    /**
     * @param string $inData
     * @param int $flags
     * @param string|null $outSign
     * @param string $alias
     * @return string
     * @throws AdapterException
     */
    public function signData(string $inData, int $flags, ?string $outSign = null, string $alias = ""): string
    {
        if (!isset($outSign)) {
            $outSign = "";
        }
        $this->call(
            KalkanCrypt_SignData($alias, $flags, $inData, $outSign)
        );
        return $outSign;
    }

    /**
     * @param int $flag
     * @param string $unsignedData
     * @param string $signedData
     * @param string $alias
     * @param int $certId
     * @return array{data: string, info: string, cert: string}
     * @throws AdapterException
     */
    public function verifyData(int $flag, string $unsignedData, string $signedData, string $alias = "", int $certId = 0): array
    {
        $outData = "";
        $outVerifyInfo = "";
        $outCert = "";
        $this->call(
            KalkanCrypt_VerifyData($alias,
                $flag,
                $unsignedData,
                $certId,
                $signedData,
                $outData,
                $outVerifyInfo,
                $outCert)
        );
        return [
            "data" => $outData,
            "info" => $outVerifyInfo,
            "cert" => $outCert
        ];
    }

    /**
     * Хэширует данные
     *
     * @param string $data входные данные
     * @param int $flags флаги
     * @param string $alias_hash алгоритм хэширования (строка “sha256” или “Gost34311_95”)
     * (можно указать во флагах)
     * @throws AdapterException
     */
    public function hashData(string $data, int $flags, string $alias_hash = ''): string
    {
        $outData = "";
        $this->call(
            KalkanCrypt_HashData($alias_hash, $flags, $data, $outData)
        );
        return $outData;
    }

    /**
     * Подписывает входные хэшированные данные.
     *
     * @param string $hash входные хэшированные данные
     * @param int $flags флаги
     * @param string $alias_hash алгоритм хэширования (строка “sha256” или “Gost34311_95”)
     * (можно указать с помощью флогов)
     * @return string
     * @throws AdapterException
     */
    public function signHash(string $hash, int $flags, string $alias_hash = ""): string
    {
        $outSignedHash = "";
        $this->call(
            KalkanCrypt_SignHash($alias_hash, $flags, $hash, $outSignedHash)
        );
        return $outSignedHash;
    }

    /**
     * Подписывает данные в формате XML.
     * @param string $xml входные данные
     * @param string $signNodeId идентификатор тэга, который необходимо подписать.
     * Не указывается, если необходимо подписать все содержимое документа
     * @param string $parentSignNode тэг, в который необходимо поместить значение подписи
     * @param string $parentNameSpace пространство имен тэга,
     * в который необходимо поместить значение подписи.
     * Если пространство имен есть, но не будет указано - то тег не найдется;
     * @param int $flags флаги
     * @param string $alias label (alias) сертификата
     * @return string
     * @throws AdapterException
     */
    public function signXML(string $xml,
                            string $signNodeId,
                            string $parentSignNode,
                            string $parentNameSpace,
                            int    $flags = 0,
                            string $alias = ""): string
    {
        $signedXml = "";
        $this->call(
            KalkanCrypt_SignXML($alias, $flags, $xml,$signedXml, $signNodeId, $parentSignNode, $parentNameSpace)
        );
        return $signedXml;
    }

    /**
     * Обеспечивает проверку подписи данных в формате XML.
     * @param string $inData входные данные
     * @param int $flags флаги
     * @param string $alias label (alias) сертификата
     * @return string
     * @throws AdapterException
     */
    public function verifyXML(string $inData, int $flags, string $alias = ""): string
    {
        $outVerifyInf = "";
        $this->call(
            KalkanCrypt_VerifyXML($alias, $flags, $inData, $outVerifyInf)
        );
        return $outVerifyInf;

    }

    /**
     * @param int $storage
     * <br/> Adapter::KCST_PKCS12
     * <br/> Adapter::KCST_KZIDCARD
     * <br/> Adapter::KCST_KAZTOKEN
     * <br/> Adapter::KCST_ETOKEN72K
     * <br/> Adapter::KCST_JACARTA
     * <br/> Adapter::KCST_X509CERT
     * <br/> Adapter::KCST_AKEY
     * @return string
     * @throws AdapterException
     */
    //TODO: how this work on backend ???
    public function getTokens(int $storage): string
    {
        $tokens = "";
        $tokens_count = 0;
        $this->call(
            KalkanCrypt_GetTokens($storage, $tokens, $tokens_count)
        );
        return $tokens;
    }

    /**
     *  Обеспечивает получение списка сертификатов в виде строки и их количество.
     * @return string
     * @throws AdapterException
     */
    public function getCertificatesList(): string
    {
        $certificates = "";
        $count = 0;
        $this->call(
            KalkanCrypt_GetCertificatesList($certificates, $count)
        );
        return $certificates;
    }

    /**
     * @param string $rawCert Cert as string
     * @param int $flag
     * @param int $type KC_USE_NOTHING, KC_USE_CRL, KC_USE_OCSP
     * @param string $path Validation Path
     * @return array ["info" => "", "OCSP_Response" => ""]
     * @throws AdapterException
     */
    public function validateCert(string $rawCert, int $flag, int $type = Adapter::KC_USE_NOTHING, string $path = ""): array
    {
        $outInfo = "";
        $getOCSPResponse = "";
        $this->call(
            KalkanCrypt_X509ValidateCertificate($rawCert, $type, $path, 0, $outInfo, $flag, $getOCSPResponse)
        );
        return [ "info" => $outInfo, "OCSP_Response" => $getOCSPResponse];
    }

    /**
     * Обеспечивает получение сертификата из XML.
     * @param string $xml
     * @param int $signId
     * @return string
     * @throws AdapterException
     */
    public function getCertFromXML(string $xml, int $signId = 0): string
    {
        $outCert = "";
        $this->call(
            KalkanCrypt_getCertFromXML($xml, $signId, $outCert)
        );
        return $outCert;
    }

    /**
     * @param string $inCMS
     * @param int $inSignID
     * @param int $flags
     * @return string
     * @throws AdapterException
     */
    public function getCertFromCMS(string $inCMS, int $inSignID, int $flags): string
    {
        $outCert = "";
        $this->call(
            KalkanCrypt_getCertFromCMS($inCMS, $inSignID, $flags, $outCert)
        );
        return $outCert;
    }

    /**
     * @param string $inZipFile
     * @param int $flags
     * @param int $inSignID
     * @return string
     * @throws AdapterException
     */
    public function getCertFromZip(string $inZipFile, int $flags = 0, int $inSignID = 0): string
    {
        $outCert = "";
        $this->call(
            KalkanCrypt_getCertFromZipFile($inZipFile, $flags, $inSignID, $outCert)
        );
        return $outCert;
    }

    /**
     * @param string $inCMS
     * @param int $flags
     * @return int
     * @throws AdapterException
     */
    public function getTimeFromSig(string $inCMS, int $flags): int
    {
        $outDateTime = 0;
        $this->call(
            KalkanCrypt_getTimeFromSig($inCMS, 0, $flags, $outDateTime)
        );
        return $outDateTime;
    }

    /**
     * Подписывает данные в формате WSSE.
     *
     * @param string $alias label (alias) сертификата
     * @param int $flags флаги
     * @param string $data входные данные
     * @param string $signNodeId идентификатор тэга, который необходимо подписать.
     * @throws AdapterException
     */
    public function signWSSE(string $data, string $signNodeId, int $flags = 0, string $alias = ""): string
    {
        $outSign = "";
        $this->call(
            KalkanCrypt_SignWSSE($alias, $flags, $data, $outSign, $signNodeId)
        );
        return $outSign;
    }

    /**
     * @param string $filePath
     * @param string $name
     * @param string $outDir
     * @param int $flags
     * @param string $alias
     * @return void
     * @throws AdapterException
     */
    public function signZipCon(string $filePath, string $name, string $outDir, int $flags = 0, string $alias = ""): void
    {
        $this->call(
            KalkanCrypt_ZipConSign($alias, $filePath, $name, $outDir, $flags)
        );
    }

    /**
     * @param string $filePath
     * @param int $flags
     * @return string
     * @throws AdapterException
     */
    public function verifyZipCon(string $filePath, int $flags = 0): string
    {
        $outInfo = "";
        $this->call(
            KalkanCrypt_ZipConVerify($filePath, $flags, $outInfo)
        );
        return $outInfo;
    }

    /**
     * Установить настройки прокси-сервера
     * @throws AdapterException
     */
    public function setProxy(int $flag_proxy, string $host = "", string $port = "", string $login = "", string $password = ""): void
    {
        $this->call(
            KalkanCrypt_SetProxy($flag_proxy, $host, $port, $login, $password)
        );
    }

    /**
     * @param string|null $TSA_url
     * @return void
     * @throws AdapterException
     */
    public function setTsaUrl(?string $TSA_url): void
    {
        $this->call(
            KalkanCrypt_TSASetUrl($TSA_url)
        );
    }

    public function finalizeXml(): void
    {
        KalkanCrypt_XMLFinalize();
    }

    /**
     * Освобождает ресурсы криптопровайдера KalkanCrypt и завершает работу библиотеки.
     * @return void
     */
    public function finalize(): void
    {
        KalkanCrypt_Finalize();
    }

    /**
     * @param string $xml_in
     * @return string
     * @throws AdapterException
     */
    public function getSigAlgFromXML(string $xml_in): string
    {
        $retSigAlg = "";
        $this->call(
            KalkanCrypt_getSigAlgFromXML($xml_in, $retSigAlg)
        );
        return $retSigAlg;
    }

    public function getLastErrorString(): string
    {
        return KalkanCrypt_GetLastErrorString();
    }

    public function getLastError(): int
    {
        return KalkanCrypt_GetLastError();
    }

    /**
     * @param int|null $func
     * @return void
     * @throws AdapterException
     */
    private function call(?int $func): void
    {
        if ($func) {
            throw new AdapterException($this->getLastErrorString(), code: $func);
        }else{
            $this->states[] = $this->getLastErrorString();
        }
    }

    public function getStates(): array
    {
        return $this->states;
    }
}