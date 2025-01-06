JSON파일을 이용한, userID, PW 데이터 저장 방식 예제

사용자 정보를 JSON이 아닌 Map에 저장하면 하드디스크가 아닌 메모리에 저장된다. 
RAM에 저장된 데이터는 휘발성 기억장치이기에 컴퓨터가 꺼질 경우 모든 정보가 날아간다.

따라서 persist 저장을 할 수 있는 보조기억장치 (HDD, SDD) 등에 데이터 저장을 위한 JSON파일 형식으로 구현하였다.

회원가입할 때마다 users.json 파일에 모든 유저 정보를 저장하고, 로그인할 때마다 users.json의 유저정보를 불러와
저장된 유저정보와 일치하는 지 여부를 확인한다.

참조: https://velog.io/@mainfn/Node.js-express로-회원가입로그인-간단-구현
