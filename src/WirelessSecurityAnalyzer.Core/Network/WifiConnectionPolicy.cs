using WirelessSecurityAnalyzer.Core.Models;

namespace WirelessSecurityAnalyzer.Core.Network;

public static class WifiConnectionPolicy
{
    public static bool IsSupported(WifiSecurityInfo security) =>
        security is { Protocol: WifiSecurityProtocol.Open, Authentication: WifiAuthenticationType.Open } ||
        // Group traffic can use TKIP while this client requests CCMP for pairwise traffic.
        security is { Protocol: WifiSecurityProtocol.Wpa2, Authentication: WifiAuthenticationType.Personal,
            GroupCipher: WifiCipherType.Ccmp or WifiCipherType.Tkip } && security.PairwiseCiphers.Contains(WifiCipherType.Ccmp);

    public static string UnsupportedMessage(WifiSecurityInfo security) => security.IsEnterprise
        ? "Данный тип аутентификации пока не поддерживается."
        : "Тип сети пока не поддерживается. Доступны Open и WPA2-Personal с поддержкой AES/CCMP для клиента.";

    public static string Message(WifiConnectionFailure failure) => failure switch
    {
        WifiConnectionFailure.None => string.Empty,
        WifiConnectionFailure.UnsupportedSecurity => "Тип сети пока не поддерживается.",
        WifiConnectionFailure.InvalidPassword => "Пароль WPA2: 8–63 печатных ASCII-символа или 64 шестнадцатеричных символа PSK.",
        WifiConnectionFailure.InvalidSsid => "Не удалось определить корректный SSID. Скрытые сети без известного имени не поддерживаются.",
        WifiConnectionFailure.NoAdapter => "Wi-Fi адаптер не обнаружен или был отключён.",
        WifiConnectionFailure.RadioOff => "Wi-Fi адаптер отключён. Включите Wi-Fi и проверьте режим «В самолёте».",
        WifiConnectionFailure.ServiceUnavailable => "Служба WLAN AutoConfig недоступна. Проверьте службу автонастройки WLAN.",
        WifiConnectionFailure.AccessDenied => "Windows запретила доступ. Проверьте разрешения местоположения и доступ для классических приложений.",
        WifiConnectionFailure.AuthenticationFailed => "Не удалось пройти аутентификацию. Проверьте пароль и настройки сети.",
        WifiConnectionFailure.NetworkUnavailable => "Выбранная сеть больше недоступна. Обновите список сетей.",
        WifiConnectionFailure.Timeout => "Истекло время ожидания подключения. Проверьте доступность сети и повторите попытку.",
        WifiConnectionFailure.AddressTimeout => "Подключено к Wi-Fi, IP-адрес ещё не получен. Сетевой аудит пока недоступен.",
        WifiConnectionFailure.Cancelled => "Подключение отменено пользователем.",
        WifiConnectionFailure.Busy => "Операция подключения уже выполняется. Дождитесь завершения или отмените её.",
        _ => "Не удалось выполнить подключение. Проверьте сеть, адаптер и параметры Windows."
    };
}
