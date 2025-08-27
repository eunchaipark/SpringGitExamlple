package com.example.myapp.hr.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.example.myapp.hr.service.IEmpService;

@Controller
public class EmpController {
	
	
	@Autowired
	IEmpService empService;
	
	@GetMapping({"/hr/count"})
	public String empCount(Model model) {
		model.addAttribute("count", empService.getEmpCount());
		return "hr/view";
	}
	
	@GetMapping("/hr/{employeeId}")
	public String getEmpInfo(@PathVariable int employeeId, Model model) {
		Map<String, Object> emp = empService.getEmpInfo(employeeId);
		model.addAttribute("emp",emp);
		return "hr/view";
	}
}
