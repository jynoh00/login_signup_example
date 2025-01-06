const express = require('express');
const path = require('path');
const fs = require('fs').promises; // 콜백함수를 기본으로 사용하는 fs 모듈을 promise 기반으로 사용할 수 있게 .promise; 형태로 불러온다.
const cookieParser = require('cookie-parser'); // ?
const app = express();
const bcrypt = require('bcrypt');

const USERS_JSON_FILENAME = 'users.json';
const USER_COOKIE_KEY = 'USER';
const PORT = 3000;

/* users.json파일의 데이터를 입력 받아와 String으로 변환 후 JSON.parse()로 자바스크립트 객체로 변환 이후 반환 - users.json의 데이터 불러오기 */
async function fetchAllUsers(){ // async 키워드 -> 일반함수를 비동기함수로 선언
    const data = await fs.readFile(USERS_JSON_FILENAME); // await 키워드 -> 동기적으로 코드 진행, fs.readFile('파일')로 data에 파일정보를 저장한다.
    const users = JSON.parse(data.toString()); // users에 json파일을 toString한걸 JSON.parse()하여 저장한다, 
                                            //JSON.parse() -> json 형식 문자열(<- toString()을 쓴 이유)을 자바스크립트 객체로 변환.
    return users; // users 객체를 반환한다. // async함수이기에 Promise.resolve()에 감싸줘서 반환된다.
}

/* fetchAllUsers()를 통해 불러온 users 데이터에서 - user 일치 여부 확인 후 해당 유저 객체를 반환, 없으면 undefined*/
async function fetchUser(username){
    const users = await fetchAllUsers(); // fetchAllUsers()의 반환값이 저장.
    const user = users.find((user) => user.username === username); // users 객체 배열을 순회하며 배열의 각 요소인 user의 .username이 username과 같은 지 검사
                                                                    // 이후 해당 user(내부 화살표 함수 인자명)객체를 user(변수명)에 할당한다.
    return user; // 객체 반환
}

/* fetchAllUsers()를 통해 불러온 users 데이터에서 newUser를 추가 후 users.json에 저장(추가 수정) */
async function createUser(newUser){
    const hashedPassword = await bcrypt.hash(newUser.password, 10); // 두번째 인자는 salt값 : 값이 클 수록 hash함수를 여러번 반복 -> 계산 속도를 줄인다.
                                                                    // salt값이 작아 속도가 빠르면 해커들의 무차별 대입이 성공할 수 있기 때문
    const users = await fetchAllUsers(); // 객체 배열을 불러온다.
    users.push({
        ...newUser,
        password: hashedPassword,
    }); // newUser라는 객체를 users 객체 배열에 push
    await fs.writeFile(USERS_JSON_FILENAME, JSON.stringify(users)); // JSON.stringify()-> 자바스크립트 값이나 객체를 JSON 문자열로 변환.
}

async function removeUser(username, password){
    const user = await fetchUser(username);
    const matchPassword = await bcrypt.compare(password, user.password);
    if (matchPassword){
        const users = await fetchAllUsers();
        const idx = users.findIndex(u => u.username === username);
        users.splice(idx, 1);
        await fs.writeFile(USERS_JSON_FILENAME, JSON.stringify(users));
    }
}

app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); // ?
app.use(express.urlencoded({ extends: true }));

app.get('/', async (req, res) => {
    const userCookie = req.cookies[USER_COOKIE_KEY]; // user라는 쿠키 데이터를 가져옴. (없을 경우 로그인 되어있지 않다는 의미)

    if (userCookie){
        const userData = JSON.parse(userCookie); // user라는 쿠키데이터를 자바스크립트 객체로 변환
        const user = await fetchUser(userData.username);
        if (user){   
            // return 붙임
            return res.status(200).send(`
                <a href = "/logout">Log Out</a>
                <a href = "/withdraw">Withdraw</a>
                <h1>id: ${userData.username}, name: ${userData.name}, password: ${userData.password}</h1>
            `);
        }
    }

    res.status(200).send(`
        <a href = "/login.html">Log In</a>
        <a href = "/signup.html">Sign Up</a>
        <h1>Not Logged In</h1> 
    `);
});

app.post('/signup', async (req, res) => {
    const { username, name, password} = req.body; // html file에서 POST (body에 담아서 보냄)
    const user = await fetchUser(username);
    if (user){ // user 객체에 값이 반환된 경우 -> 이미 존재하는 user일 경우
        return res.status(400).send(`dupulicate username: ${username}`);
    }

    if (username === '' || name === '' || password == ''){
        return res.status(400).send(`Please fill in all the fields`);
    }

    const newUser = {
        username,
        name,
        password
    };
    await createUser(newUser);

    res.cookie(USER_COOKIE_KEY, JSON.stringify(newUser)); // 가입하면 바로 로그인 되게 하기 위해 -> 쿠키값이 존재하니까 [38 ~ 40줄]
    res.redirect('/'); // 가입 완료 후 root 페이지로 이동.
});

app.post('/login', async (req, res) => { // login POST 과정은 동기로 해도 돼? -> 작성자 오류인 듯 (await을 하려는 곳이 비동기 함수여야 함.)
    const { username, password } = req.body;
    const user = await fetchUser(username);

    if (username === '' || password == ''){
        return res.status(400).send(`Please fill in all the fields`);
    }

    if (!user){ // 반환된 객체가 존재하지 않을 경우(undefined) -> 회원가입이 안되어 있는 객체일 경우
        return res.status(400).send(`not registered username: ${username}`);
    }
    
    const matchPassword = await bcrypt.compare(password, user.password); // json파일에 있는 password (hashing된)가 입력한 password의 hashing값과 같은 지
    if (!matchPassword){
        return res.status(400).send(`incorrect password`);
    }

    res.cookie(USER_COOKIE_KEY, JSON.stringify(user)); // user객체를 문자열 형태로 변환하여 쿠키에 저장
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.clearCookie(USER_COOKIE_KEY);
    res.redirect('/');
});

app.get('/withdraw', async (req, res) => {
    const userCookie = req.cookies[USER_COOKIE_KEY];
    if (!userCookie) return res.redirect('/'); // 로그인되어있지 않은 상황에서 url을 통해 get메소드에 접근할 경우 방지.

    const user = JSON.parse(userCookie);
    await removeUser(user.username, user.password);
    res.clearCookie(USER_COOKIE_KEY);
    res.redirect('/');
});

app.listen(PORT, () => {
    console.log('server is running at 3000');
});