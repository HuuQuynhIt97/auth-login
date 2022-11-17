using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authentication.Dtos
{
    public class UpdateUserDto
    {
        public int ID { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public int OCID { get; set; }
        public int LevelOC { get; set; }
        public string EmployeeID { get; set; }
        public string Email { get; set; }
        public int RoleID { get; set; }
        public string ImageURL { get; set; }
        public string AccessTokenLineNotify { get; set; }
        public byte[] ImageBase64 { get; set; }
        public bool isLeader { get; set; }
        public bool IsShow { get; set; }
        public int SystemCode { get; set; }
        public int DeleteBy { get; set; }
        public DateTime ModifyTime { get; set; }
    }
}
