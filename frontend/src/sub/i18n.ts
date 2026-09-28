/**
 * The subscription page is read by subscribers, not operators, so unlike the admin UI it
 * speaks the reader's language. Two languages, picked from the browser; anything else gets
 * English.
 */

const en = {
  title: "Your subscription",
  loading: "Loading",
  notFound: "This subscription does not exist or has been revoked. Ask for a new link.",
  rateLimited: "Too many requests. Wait a minute and reload the page.",
  failed: "The subscription could not be loaded. Try again later.",

  status: { active: "Active", limited: "Traffic used up", expired: "Expired", disabled: "Disabled" },
  inactive: {
    limited: "The traffic allowance is used up. The servers will return when it resets or is raised.",
    expired: "The subscription has expired. The servers will return once it is renewed.",
    disabled: "The subscription is switched off.",
  },

  traffic: "Traffic",
  ofLimit: (used: string, limit: string) => `${used} of ${limit}`,
  unlimited: (used: string) => `${used} used, no limit`,
  expires: "Valid until",
  never: "No end date",
  resets: "Resets",
  reset: { never: "Never", daily: "Daily", weekly: "Weekly", monthly: "Monthly" },

  addTitle: "Add to your app",
  addHint:
    "Open this page on the device you want to connect, then tap your app below. If your app is not listed, copy the link and add it as a subscription.",
  link: "Subscription link",
  copy: "Copy",
  copied: "Copied",
  showQr: "Show QR code",
  hideQr: "Hide QR code",
  qrHint: "Scan with the app on another device.",
  openIn: (app: string) => `Open in ${app}`,

  downloadTitle: "Download a profile",
  downloadHint: "For apps that import a file rather than a link.",

  serversTitle: "Individual servers",
  serversHint: "For apps that take one server at a time. These change when the subscription does; the link above keeps itself up to date.",
  noServers: "No servers are available on this subscription right now.",

  stepsTitle: "How to connect",
  steps: [
    "Install one of the apps listed above.",
    "Tap its button, or copy the link and add it in the app as a subscription.",
    "Choose a server and connect. The app refreshes the list by itself.",
  ],
};

type Dictionary = typeof en;

const ru: Dictionary = {
  title: "Ваша подписка",
  loading: "Загрузка",
  notFound: "Такой подписки нет или она отозвана. Попросите новую ссылку.",
  rateLimited: "Слишком много запросов. Подождите минуту и обновите страницу.",
  failed: "Не удалось загрузить подписку. Попробуйте позже.",

  status: { active: "Активна", limited: "Трафик исчерпан", expired: "Истекла", disabled: "Отключена" },
  inactive: {
    limited: "Трафик закончился. Серверы вернутся после сброса или увеличения лимита.",
    expired: "Срок подписки истёк. Серверы вернутся после продления.",
    disabled: "Подписка отключена.",
  },

  traffic: "Трафик",
  ofLimit: (used, limit) => `${used} из ${limit}`,
  unlimited: (used) => `${used}, без лимита`,
  expires: "Действует до",
  never: "Бессрочно",
  resets: "Сброс",
  reset: { never: "Нет", daily: "Ежедневно", weekly: "Еженедельно", monthly: "Ежемесячно" },

  addTitle: "Добавить в приложение",
  addHint:
    "Откройте эту страницу на устройстве, которое хотите подключить, и нажмите на своё приложение ниже. Если его нет в списке — скопируйте ссылку и добавьте её как подписку.",
  link: "Ссылка подписки",
  copy: "Копировать",
  copied: "Скопировано",
  showQr: "Показать QR-код",
  hideQr: "Скрыть QR-код",
  qrHint: "Отсканируйте приложением на другом устройстве.",
  openIn: (app) => `Открыть в ${app}`,

  downloadTitle: "Скачать профиль",
  downloadHint: "Для приложений, которые импортируют файл, а не ссылку.",

  serversTitle: "Отдельные серверы",
  serversHint:
    "Для приложений, которые принимают по одному серверу. Они меняются вместе с подпиской; ссылка выше обновляется сама.",
  noServers: "Сейчас в подписке нет доступных серверов.",

  stepsTitle: "Как подключиться",
  steps: [
    "Установите одно из приложений из списка выше.",
    "Нажмите на его кнопку или скопируйте ссылку и добавьте её в приложении как подписку.",
    "Выберите сервер и подключитесь. Список приложение обновляет само.",
  ],
};

export type Language = "en" | "ru";

export function pickLanguage(preferred: readonly string[]): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split("-")[0];
    if (base === "ru" || base === "en") return base;
  }
  return "en";
}

export const dictionaries: Record<Language, Dictionary> = { en, ru };
