using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Dtos
{
    public class UserDto
    {
        public int ID { get; set; }
        public string Username { get; set; }
        public string EmployeeID { get; set; }
        public string Email { get; set; }
        public int RoleID { get; set; }
        public string RoleName { get; set; }
        public bool isLeader { get; set; }
    }
}
