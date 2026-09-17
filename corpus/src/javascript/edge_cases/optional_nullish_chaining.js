const data = {
    user: { name: "ada", profile: null },
    items: [{ price: 10 }, null, { price: 20 }],
};

const profileAge = data?.user?.profile?.age ?? -1;
const firstPrice = data?.items?.[0]?.price ?? 0;
const middlePrice = data?.items?.[1]?.price ?? "none";
const callMaybe = data?.user?.greet?.() ?? "no greet";
const chainedZero = 0 ?? "default";
const chainedEmpty = "" ?? "default";

console.log({ profileAge, firstPrice, middlePrice, callMaybe, chainedZero, chainedEmpty });
