package com.example.myapp.hr.dao;

import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Mapper
@Repository
public interface IEmpRepository {
	int getEmpCount();
	Map<String, Object> getEmpInfo(int empid);
}
