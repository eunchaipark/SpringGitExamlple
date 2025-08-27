package com.example.myapp.member.controller;

import java.security.Principal;
import java.util.UUID;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.myapp.member.MemberValidator;
import com.example.myapp.member.model.Member;
import com.example.myapp.member.service.IMemberService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Controller
public class MemberController {
	static final Logger logger = LoggerFactory.getLogger(MemberController.class);

	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired
	IMemberService memberService;

	@Autowired
	MemberValidator memberValidator;

	
	@InitBinder
	private void initBinder(WebDataBinder binder) {
		binder.setValidator(memberValidator);
	}
	
	@RequestMapping(value="/member/insert", method=RequestMethod.GET)
	public String insertMember(HttpSession session, Model model) {
		String csrfToken =UUID.randomUUID().toString();
		session.setAttribute("csrfToken", csrfToken);
		logger.info("/member/insert, GET", csrfToken);
		model.addAttribute("member",new Member());
		return "member/form";
	}
	
	@RequestMapping(value="/member/insert", method=RequestMethod.POST)
	public String insertMember(@Validated Member member, BindingResult result, HttpSession session, Model model) {

	    // 1. 유효성 검사
	    if(result.hasErrors()) {
	        model.addAttribute("member", member);
	        return "member/form";
	    }

	    // 2. 비밀번호 확인
	    if(!member.getPassword().equals(member.getPassword2())) {
	        model.addAttribute("member", member);
	        model.addAttribute("message", "MEMBER_PW_RE");
	        return "member/form";
	    }

	    // 3. 비밀번호 암호화 후 저장
	    String encodedPw = passwordEncoder.encode(member.getPassword());
	    member.setPassword(encodedPw);

	    // 4. 회원 등록
	    try {
	        memberService.insertMember(member);
	    } catch(DuplicateKeyException e) {
	        member.setUserid(null);
	        model.addAttribute("member", member);
	        model.addAttribute("message", "ID_ALREADY_EXIST");
	        return "member/form";
	    }

	    // 5. 세션 종료 후 홈으로 이동
	    session.invalidate();
	    return "home";
	}

	
	@RequestMapping(value="/member/login", method=RequestMethod.GET)
	public String login() {
		return "member/login";
	}
	
	@RequestMapping(value="/member/login", method=RequestMethod.POST)
	public String login(String userid, String password, HttpSession session, Model model) {
		Member member = memberService.selectMember(userid);
		if(member != null) {
			String dbPassword = member.getPassword();
				if(dbPassword == null) {
				//아이디가 없음
				model.addAttribute("message", "NOT_VALID_USER");
			}else {
				//아이디 있음
				if(dbPassword.equals(password)) {
					//비밀번호 일치
					session.setAttribute("userid", userid);
					session.setAttribute("name", member.getName());
					session.setAttribute("email", member.getEmail());
					return "member/login";
				}else {
					//비밀번호 불일치
					model.addAttribute("message", "WRONG_PASSWORD");
				}
			}
		}else {
			model.addAttribute("message", "USER_NOT_FOUND");
		}
		session.invalidate();	
		return "member/login";
	}
	
	@RequestMapping(value="/member/logout", method=RequestMethod.GET)
	public String logout(HttpSession session, HttpServletRequest request) {
		session.invalidate(); //로그아웃
		return "home";
	}
	
	@GetMapping(value="/member/update")
	public String updateMember(Model model) {
	    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
	    String userid = (auth != null) ? auth.getName() : null;

	    if(userid != null && !userid.isEmpty()) {
	        Member member = memberService.selectMember(userid);
	        model.addAttribute("member", member);
	        model.addAttribute("message", "UPDATE_USER_INFO");
	        return "member/update";
	    } else {
	        // 로그인하지 않은 사용자
	        model.addAttribute("message", "NOT_LOGIN_USER");
	        return "member/login";
	    }
	}
	
	@PostMapping(value="/member/update")
	public String updateMember(@Validated Member member,BindingResult result, Principal principal, Model model) {
		member.setUserid(principal.getName());
		if(result.hasErrors()) {
			model.addAttribute("member",member);
			return "member/update";
		}
		try{
			memberService.updateMember(member);
			model.addAttribute("message", "UPDATED_MEMBER_INFO");
			model.addAttribute("member", member);
			return "member/login";
		}catch(Exception e){
			model.addAttribute("message", e.getMessage());
			e.printStackTrace();
			return "member/error";
		}
	}
	
	@GetMapping(value="/member/delete")
	public String deleteMember(Principal principal, Model model) {
		String userid = principal.getName();
		if(userid != null && !userid.equals("")) {
			Member member = memberService.selectMember(userid);
			model.addAttribute("member", member);
			model.addAttribute("message", "MEMBER_PW_RE");
			return "member/delete";
		}else {
			//userid가 세션에 없을 때 (로그인 하지 않았을 때)
			model.addAttribute("message", "NOT_LOGIN_USER");
			return "member/login";
		}
	}
	
	@PostMapping(value="/member/delete")
	public String deleteMember(String password, Principal principal, RedirectAttributes model) {
		try {
			Member member = new Member();
			member.setUserid(principal.getName());
			String dbpw = memberService.getPassword(member.getUserid());
			if(password != null && passwordEncoder.matches(password, dbpw)) {
				member.setPassword(dbpw);
				memberService.deleteMember(member) ;
				model.addFlashAttribute("message","delete-user_info");
				return "redirect:/member/logout";
			}else {
				model.addAttribute("message", "WRONG_PASSWORD");
				return "member/delete";
			}
		}catch(Exception e){
			model.addAttribute("message", "DELETE_FAIL");
			e.printStackTrace();
			return "member/delete";
		}
	}
	
	
}