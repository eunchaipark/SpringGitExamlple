package com.example.myapp.hr.service;

import java.util.Map;

public interface IEmpService {
	int getEmpCount();
	
	Map<String, Object> getEmpInfo(int empid);
}
