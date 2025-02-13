
function makeCashFlow(trsDate, amount, transactions) {
    //transactions is array with this format [{date:'', amount:'', ....}]

    const initialInvestment = {
        date: trsDate,
        amount: -Math.abs(Number(amount))
    };

    const transactionArray = transactions
        .filter(item => ['sell', 'dividend', 'redeem', 'interest', 'capReduct'].includes(item.transaction_type)) 
        .map(item => ({
        date: item.date,
        amount: Number(item.amount)
        }));

    const filteredArray = [initialInvestment, ...transactionArray];
    filteredArray.sort((a, b) => new Date(a.date) - new Date(b.date));
    return filteredArray;
}

function xirr(data) {
    // this data is is array with this format [{date:'', amount:'', ....}]

    const dates = data.map(d => new Date(d.date));
    const amounts = data.map(d => d.amount);

    const startDate = dates[0];
    const endDate = dates[dates.length - 1];

    const daysBetween = (start, end) => (end - start) / (1000 * 60 * 60 * 24);

    const npv = (rate) => {
        let result = 0;
        for (let i = 0; i < data.length; i++) {
        const time = daysBetween(startDate, dates[i]) / 365; // 연도 단위로 변환
        result += amounts[i] / Math.pow(1 + rate, time);
        }
        return result;
    };

    let guess = 0.1; // 초기 추정값
    let tolerance = 1e-6; // 오차 범위
    let iteration = 0;
    let maxIterations = 1000;

    // 반복적으로 NPV가 0에 가까워질 때까지 IRR을 찾는다.
    while (iteration < maxIterations) {
    const f = npv(guess);
    const fPrime = (npv(guess + tolerance) - f) / tolerance; // 유도된 함수

    const newGuess = guess - f / fPrime; // Newton-Raphson 공식

    if (Math.abs(newGuess - guess) < tolerance) {
        return newGuess * 100; // 백분율로 반환
    }

    guess = newGuess;
    iteration++;
    }

    return NaN;
}
