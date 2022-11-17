using System.Collections.Generic;
using System.Linq;
using Authentication.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ValuesController : ControllerBase
    {
        private readonly ILogger<ValuesController> _logger;
        private readonly DataContext _context;

        public ValuesController(ILogger<ValuesController> logger, DataContext context)
        {
            _logger = logger;
            _context = context;
        }

        //[HttpGet]
        //public IEnumerable<string> Get()
        //{
        //    var userName = User.Identity?.Name;
        //    _logger.LogInformation($"User [{userName}] is viewing values.");
        //    return new[] { "value1", "value2" };
        //}
        [HttpGet]
        public IActionResult Get()
        {
          
            return Ok(_context.Users.ToList());
        }
    }
}
