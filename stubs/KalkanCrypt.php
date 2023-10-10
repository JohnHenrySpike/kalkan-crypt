<?php
/** @noinspection PhpInconsistentReturnPointsInspection */
/** @noinspection PhpUnusedFunctionInspection */

/**
 * Инициализация библиотеки.
 */
function KalkanCrypt_Init(): int {}

/**
 * Установить настройки прокси-сервера.
 *
 * @param int $flags флаги
 * @param string $host адрес прокси-сервера
 * @param string $port порт
 * @param string $login имя пользователя
 * @param string $password пароль
 * @return int
 */
function KalkanCrypt_SetProxy(int $flags, string $host, string $port, string $login, string $password): int {}

/**
 * Установка адреса сервиса TSA.
 * <br/>Значение по умолчанию http://tsp.pki.gov.kz:80
 * @param string $url адрес сервиса TSA
 * @return int
 */
function KalkanCrypt_TSASetUrl(string $url): int {}

/**
 * Загрузка ключей/сертификата их хранилища.
 *
 * @param int $storage тип хранилища
 * @param string $password пароль к хранилищу
 * @param string $container название хранилища (путь)
 * @param string $alias label (alias) сертификата
 * @return int
 */
function KalkanCrypt_LoadKeyStore(int $storage, string $password, string $container, string $alias):int {}

/**
 * Обеспечивает получение значений полей/расширений из сертификата.<br/>
 * Сертификат должен быть предварительно загружен с помощью одной из функций:<br/>
 * LoadKeyStore(), X509LoadCertificateFromFile(),X509LoadCertificateFromBuffer().
 *
 * @param int $prop_id идентификатор полей/расширений сертификата
 * @param string $cert сертификат в виде строки
 * @param string $data значение указанного поля/расширения
 * @return int
 */
function KalkanCrypt_X509CertificateGetInfo(int $prop_id, string $cert, string &$data): int {}

/**
 * Экспорт сертификата из хранилища.
 *
 * @param string $alias label (alias) сертификата
 * @param int $encoding_flags флаги
 * @param string $cert сертификат в виде строки
 * @return int
 */
function KalkanCrypt_X509ExportCertificateFromStore(string $alias, int $encoding_flags, string &$cert): int {}

/**
 *Загрузка сертификата из файла для дальнейшей работы с ним.
 * @param int $type тип сертификата
 * @param string $path путь до файла сертификата
 * @return int
 */
function KalkanCrypt_X509LoadCertificateFromFile(int $type, string $path): int {}

/**
 * Загрузка сертификата из памяти.
 * @param string $cert сертификат в виде строки
 * @param int $flag флаги. Указывается кодировка сертификата
 * @return int
 */
function KalkanCrypt_X509LoadCertificateFromBuffer(string $cert, int $flag): int {}

/**
 * Подписывает данные.
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги. Устанавливают формат входных/выходных данных, тип подписи
 * @param string $data входные данные
 * @param string $sign выходные данные (подписи)
 * @return int
 */
function KalkanCrypt_SignData(string $alias, int $flags, string $data, string &$sign): int {}

/**
 * Обеспечивает проверку подписи.
 *
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги
 * @param string $inData входные данные
 * @param int $inCertID идентификатор (порядковый номер) сертификата (начинается с 0)
 * @param string $inSign подписанные входные данные
 * @param string $outData выходные данные
 * @param string $outVerifyInfo выходная подробная информация о результате проверки подписи
 * @param string $outCert указатель на начало сертификата с подробной информацией
 * @return int
 */
function KalkanCrypt_VerifyData(string $alias,
                                int    $flags,
                                string $inData,
                                int    $inCertID,
                                string $inSign,
                                string &$outData,
                                string &$outVerifyInfo,
                                string &$outCert): int {}

/**
 * Хэширует данные.
 *
 * @param string $algorithm алгоритм хэширования (строка “sha256” или “Gost34311_95”)
 * @param int $flags флаги
 * @param string $inData входные данные
 * @param string $outData выходные хэшированные данные
 * @return int
 */
function KalkanCrypt_HashData(string $algorithm, int $flags, string $inData, string &$outData): int {}

/**
 * Подписывает входные хэшированные данные.
 *
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги
 * @param string $inHash входные хэшированные данные
 * @param string $outSign выходные данные
 * @return int
 */
function KalkanCrypt_SignHash(string $alias, int $flags, string $inHash, string &$outSign): int {}

/**
 * Подписывает данные в формате XML.
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги
 * @param string $xml входные данные
 * @param string $signedXml выходные данные (подписи)
 * @param string $signNodeId идентификатор тэга, который необходимо подписать.
 * Не указывается, если необходимо подписать все содержимое документа
 * @param string $parentSignNode идентификатор тэга, в который необходимо поместить значение подписи
 * @param string $parentNameSpace пространство имен тэга,
 * в который необходимо поместить значение подписи.
 * Если пространство имен есть, но не будет указано - то тег не найдется;
 * @return int
 */
function KalkanCrypt_SignXML(string $alias,
                             int    $flags,
                             string $xml,
                             string &$signedXml,
                             string $signNodeId,
                             string $parentSignNode,
                             string $parentNameSpace): int {}

/**
 * Обеспечивает проверку подписи данных в формате XML.
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги
 * @param string $inData входные данные
 * @param string $outVerifyInf выходная подробная информация о результате проверки подписи
 * @return int
 */
function KalkanCrypt_VerifyXML(string $alias, int $flags, string $inData, string &$outVerifyInf): int {}

/**
 * Обеспечивает получение указателя на строку подключенных устройств типа storage и их количество.
 *
 * @param int $storage тип хранилища
 * @param string $tokens указатель на строку подключенных устройств
 * @param int $tk_count количество подключенных устройств
 * @return int
 */
function KalkanCrypt_GetTokens(int $storage, string &$tokens, int &$tk_count): int {}

/**
 * Обеспечивает получение списка сертификатов в виде строки и их количество.
 *
 * @param string $certificates [certAlias] указатель на строку сертификатов
 * @param int $cert_count количество сертификатов
 * @return int
 */
function KalkanCrypt_GetCertificatesList(string &$certificates, int &$cert_count): int {}

/**
 * Осуществляет проверку сертификата:
 * <br/> - проверка срока действия,
 * <br/> - построение цепочки сертификатов,
 * <br/> - проверка отозванности по OCSP или CRL.
 *
 * @param string $cert сертификат в виде строки
 * @param int $validType тип проверки (OCSP/CRL)
 * @param ?string $validPath путь до CRL или URL OCSP
 * @param int $checkTime дата и время, на момент которого необходимо провести проверку (зарезервировано, в текущей версии не используется);
 * @param string $outInfo выходная подробная информация о результате проверки
 * @param int $flags флаги
 * @param string $ocspResponse ответ от OCSP сервиса в текстовом формате и в формате BASE64
 * @return int
 */
function KalkanCrypt_X509ValidateCertificate(string $cert,
                                             int    $validType,
                                             ?string $validPath,
                                             int    $checkTime,
                                             string &$outInfo,
                                             int    $flags,
                                             string &$ocspResponse): int {}

/**
 * Обеспечивает получение сертификата из XML.
 * @param string $inXML входные данные в формате XML;
 * @param int $inSignID идентификатор сертификата
 * @param string $outCert сертификат в виде строки
 * @return int
 */
function KalkanCrypt_getCertFromXML(string $inXML, int $inSignID, string &$outCert): int {}

/**
 * Обеспечивает получение алгоритма подписи из XML.
 * @param string $xml_in входные данные в формате XML
 * @param string $retSigAlg алгоритм подписи
 * @return int
 */
function KalkanCrypt_getSigAlgFromXML(string $xml_in, string &$retSigAlg): int {}

/**
 * Обеспечивает получение сертификата из CMS.
 * @param string $inCMS входные данные в формате XML
 * @param int $inSignID идентификатор сертификата
 * @param int $flags флаги
 * @param string $outCert сертификат в виде строки
 * @return int
 */
function KalkanCrypt_getCertFromCMS(string $inCMS, int $inSignID, int $flags, string &$outCert): int {}

/**
 * Получить время подписи.
 *
 * @param string $inCMS входные данные (подпись, в текущей версии только формата CAdES)
 * @param int $inSignID идентификатор подписи (в текущей версии не используется)
 * @param int $flags флаги
 * @param int $outDateTime выходные данные, время подписи UTC в Unix формате (отсчет от 01/01/1970)
 * @return int
 */
function KalkanCrypt_getTimeFromSig(string $inCMS, int $inSignID, int $flags, int &$outDateTime): int {}

/**
 * Подписывает данные в формате WSSE.
 *
 * @param string $alias label (alias) сертификата
 * @param int $flags флаги
 * @param string $inData входные данные
 * @param string $outSign выходные данные (подписи)
 * @param string $signNodeId идентификатор тэга, который необходимо подписать.
 * <br/> Не указывается, если необходимо подписать все содержимое документа.
 * @return int
 */
function KalkanCrypt_SignWSSE(string $alias, int $flags, string $inData, string &$outSign, string &$signNodeId): int {}

/**
 * Подпись файлов с последующим размещением их в zip-контейнер
 *
 * @param string $alias label (alias) сертификата
 * @param string $filePath файлы, которые необходимо записать.
 * <br/>(В конце каждого пути к файлу необходимо вставить вертикальную линию - «|», например: inFiles= “ test/1.pdf|test/2.txt|”);
 * @param string $name имя создаваемого архива
 * @param string $outDir расположение создаваемого архива
 * @param int $flags флаги
 * @return int
 */
function KalkanCrypt_ZipConSign(string $alias, string $filePath, string $name, string $outDir, int $flags): int {}

/**
 * Проверка подписи электронных документов (zip-контейнер)
 * @param string $filePath имя ZIP-файла
 * @param int $flags флаги(В текущей версии не используется)
 * @param string $outInfo подробная информация о результате проверки подписи
 * @return int
 */
function KalkanCrypt_ZipConVerify(string $filePath, int $flags, string &$outInfo): int {}

/**
 * Обеспечивает получение сертификата из ZIP.
 * @param string $inZipFile входные данные в формате ZIP
 * @param int $flags флаги
 * @param int $inSignID идентификатор сертификата
 * @param string $outCert сертификат в виде строки
 * @return int
 */
function KalkanCrypt_getCertFromZipFile(string $inZipFile, int $flags, int $inSignID, string &$outCert): int {}

/**
 * Освобождает память и завершает работу библиотеки с модулями,
 * отвечающие за парсинг, подпись и проверку данных в формате XML.
 * <br/> Не надо вызывать каждый раз при подписи. Можно только один раз после цикла подписания xml файлов.
 */
function KalkanCrypt_XMLFinalize(): void {}

/**
 * Обеспечивает получение подробного протокола работы функций криптопровайдера KalkanCrypt
 */
function KalkanCrypt_GetLastErrorString():string {}

/**
 * Обеспечивает получение подробного кода ошибки, возникшей в процессе выполнения функций криптопровайдера KalkanCrypt
 */
function KalkanCrypt_GetLastError(): int {}

/**
 * Освобождает ресурсы криптопровайдера KalkanCrypt и завершает работу библиотеки.
 */
function KalkanCrypt_Finalize(): void {}