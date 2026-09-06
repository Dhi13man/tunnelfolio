"use strict";

export function createProfileSymbol() {
  const symbol = document.createElement("span");
  symbol.className = "profile-symbol";
  symbol.setAttribute("aria-hidden", "true");
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("class", "icon");
  icon.setAttribute("focusable", "false");
  icon.append(document.createElementNS("http://www.w3.org/2000/svg", "use"));
  const emoji = document.createElement("span");
  emoji.className = "profile-emoji";
  symbol.append(icon, emoji);
  return symbol;
}

export function updateProfileSymbol(symbol, profile) {
  const emoji = profile.emoji || "";
  const text = symbol.querySelector(".profile-emoji");
  if (text.textContent !== emoji) text.textContent = emoji;
  text.hidden = !emoji;
  const icon = symbol.querySelector(".icon");
  icon.toggleAttribute("hidden", Boolean(emoji));
  icon.firstElementChild.setAttribute("href", profile.protocol === "wireguard" ? "#icon-wireguard" : "#icon-openvpn");
}
